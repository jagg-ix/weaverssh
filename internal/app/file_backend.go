package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"weaverssh/filebackend"
	"weaverssh/storageadapter"
)

const (
	EnvFileCore        = "WEAVERSSH_FILE_CORE"
	EnvFileCorePath    = "WEAVERSSH_FILE_CORE_PATH"
	EnvFileCoreConfig  = "WEAVERSSH_FILE_CORE_CONFIG"
	EnvFileHooksConfig = "WEAVERSSH_FILE_HOOKS_CONFIG"
)

type FileBackendConfig struct {
	Root      string
	ReadOnly  bool
	Service   filebackend.API
	CoreStore filebackend.Store
	Hooks     *filebackend.Registry
}

func resolveFileBackend(config FileBackendConfig) (filebackend.API, bool, error) {
	root := strings.TrimSpace(config.Root)
	if root == "" {
		return nil, false, errors.New("file backend: root is required")
	}
	if config.Service != nil {
		description := config.Service.Describe()
		if err := sameExportRoot(root, description.Root); err != nil {
			return nil, false, err
		}
		if description.ReadOnly && !config.ReadOnly {
			return nil, false, errors.New("file backend: read-only service cannot be exposed as writable")
		}
		return config.Service, false, nil
	}

	hooks := config.Hooks
	if hooks == nil {
		path := strings.TrimSpace(os.Getenv(EnvFileHooksConfig))
		if path != "" {
			loaded, err := filebackend.LoadHooksFile(path, func(failure filebackend.Failure) {
				log.Printf("file hook operation=%s phase=%s mode=%s error=%v", failure.Operation, failure.Phase, failure.Mode, failure.Err)
			})
			if err != nil {
				return nil, false, fmt.Errorf("file backend: load hooks: %w", err)
			}
			hooks = loaded
		}
	}

	store := config.CoreStore
	ownedStore := false
	if store == nil {
		adapterPath := strings.TrimSpace(os.Getenv(EnvFileCoreConfig))
		kind := strings.ToLower(strings.TrimSpace(os.Getenv(EnvFileCore)))
		if adapterPath != "" && kind != "" {
			return nil, false, fmt.Errorf("file backend: %s and %s are mutually exclusive", EnvFileCoreConfig, EnvFileCore)
		}
		if adapterPath != "" {
			adapterConfig, err := storageadapter.LoadConfigFile(adapterPath)
			if err != nil {
				return nil, false, fmt.Errorf("file backend: load storage adapter: %w", err)
			}
			if adapterConfig.Path != "" {
				if err := validateCoreOutsideExport(root, adapterConfig.Path); err != nil {
					return nil, false, err
				}
			}
			adapter, err := filebackend.OpenAdapterStore(context.Background(), adapterConfig)
			if err != nil {
				return nil, false, fmt.Errorf("file backend: open storage adapter: %w", err)
			}
			store = adapter
			ownedStore = true
		} else {
			switch kind {
			case "", "memory":
				store = filebackend.NewMemoryStore()
				ownedStore = true
			case "rocksdb":
				path := strings.TrimSpace(os.Getenv(EnvFileCorePath))
				if path == "" {
					return nil, false, fmt.Errorf("file backend: %s is required when %s=rocksdb", EnvFileCorePath, EnvFileCore)
				}
				if err := validateCoreOutsideExport(root, path); err != nil {
					return nil, false, err
				}
				rocks, err := filebackend.OpenRocksDB(path)
				if err != nil {
					return nil, false, err
				}
				store = rocks
				ownedStore = true
			default:
				return nil, false, fmt.Errorf("file backend: unsupported core %q", kind)
			}
		}
	}

	osBackend, err := filebackend.NewOSBackend(root)
	if err != nil {
		if ownedStore {
			_ = store.Close()
		}
		return nil, false, err
	}
	var backend filebackend.Backend = osBackend

	service, err := filebackend.New(filebackend.Config{
		Backend: backend, CoreStore: store, Hooks: hooks, ReadOnly: config.ReadOnly,
		CoreReporter: func(err error) { log.Printf("file backend core: %v", err) },
	})
	if err != nil {
		if ownedStore {
			_ = store.Close()
		}
		if closer, ok := backend.(interface{ Close() error }); ok {
			_ = closer.Close()
		}
		return nil, false, err
	}
	return service, true, nil
}

func sameExportRoot(left, right string) error {
	leftResolved, err := resolveExistingDirectory(left)
	if err != nil {
		return fmt.Errorf("file backend: resolve configured root: %w", err)
	}
	rightResolved, err := resolveExistingDirectory(right)
	if err != nil {
		return fmt.Errorf("file backend: resolve service root: %w", err)
	}
	if filepath.Clean(leftResolved) != filepath.Clean(rightResolved) {
		return errors.New("file backend: service root does not match exported root")
	}
	return nil
}

func validateCoreOutsideExport(root, corePath string) error {
	rootResolved, err := resolveExistingDirectory(root)
	if err != nil {
		return fmt.Errorf("file backend: resolve export root: %w", err)
	}
	coreResolved, err := resolvePossiblyMissingPath(corePath)
	if err != nil {
		return fmt.Errorf("file backend: resolve core path: %w", err)
	}
	if pathContains(rootResolved, coreResolved) || pathContains(coreResolved, rootResolved) {
		return errors.New("file backend: storage core and exported root must not overlap")
	}
	return nil
}

func pathContains(parent, child string) bool {
	relative, err := filepath.Rel(filepath.Clean(parent), filepath.Clean(child))
	if err != nil {
		return false
	}
	return relative == "." || relative == "" || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative))
}

func resolvePossiblyMissingPath(path string) (string, error) {
	absolute, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(absolute); err == nil {
		return resolved, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	current := absolute
	missing := []string{}
	for {
		if resolved, err := filepath.EvalSymlinks(current); err == nil {
			for index := len(missing) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, missing[index])
			}
			return filepath.Clean(resolved), nil
		} else if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", errors.New("no existing ancestor for path")
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
}

func resolveExistingDirectory(path string) (string, error) {
	absolute, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", errors.New("path is not a directory")
	}
	return resolved, nil
}
