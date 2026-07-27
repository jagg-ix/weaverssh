package app

import (
	"os"
	"path/filepath"
	"testing"

	"weaverssh/filebackend"
)

func TestValidateCoreOutsideExportRejectsOverlap(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "export")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, core := range []string{
		filepath.Join(root, "core"),
		root,
		parent,
	} {
		if err := validateCoreOutsideExport(root, core); err == nil {
			t.Fatalf("core=%q should overlap export=%q", core, root)
		}
	}
	outside := filepath.Join(t.TempDir(), "state", "rocks")
	if err := validateCoreOutsideExport(root, outside); err != nil {
		t.Fatalf("outside core rejected: %v", err)
	}
}

func TestResolveFileBackendRejectsReadOnlyServiceAsWritable(t *testing.T) {
	root := t.TempDir()
	service, err := filebackend.NewOSService(root, true, filebackend.NewMemoryStore(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	if _, _, err := resolveFileBackend(FileBackendConfig{Root: root, Service: service, ReadOnly: false}); err == nil {
		t.Fatal("expected read-only/writable mismatch rejection")
	}
	resolved, owned, err := resolveFileBackend(FileBackendConfig{Root: root, Service: service, ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if resolved != service || owned {
		t.Fatalf("resolved=%T owned=%v", resolved, owned)
	}
}

func TestResolveFileBackendDefaultsToMemoryCore(t *testing.T) {
	t.Setenv(EnvFileCore, "")
	t.Setenv(EnvFileCorePath, "")
	t.Setenv(EnvFileHooksConfig, "")
	service, owned, err := resolveFileBackend(FileBackendConfig{Root: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if !owned {
		t.Fatal("generated service should be owned by local services")
	}
	defer service.Close()
	if description := service.Describe(); description.Core.Store != "memory" {
		t.Fatalf("description=%+v", description)
	}
}
