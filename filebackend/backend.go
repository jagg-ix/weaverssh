package filebackend

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// File is the bounded file handle surface used by the 9P and fs-ops servers.
type File interface {
	io.ReaderAt
	io.WriterAt
	io.Closer
	Chmod(os.FileMode) error
}

// Backend is the filesystem implementation behind the file service. Paths passed
// to methods other than Resolve are absolute paths returned by Resolve.
type Backend interface {
	Name() string
	Root() string
	Resolve(relative string) (string, error)
	Stat(path string) (os.FileInfo, error)
	Lstat(path string) (os.FileInfo, error)
	ReadDir(path string) ([]os.DirEntry, error)
	Open(path string) (File, error)
	OpenFile(path string, flag int, perm os.FileMode) (File, error)
	Truncate(path string, size int64) error
	Mkdir(path string, perm os.FileMode) error
	Remove(path string) error
	Rename(oldPath, newPath string) error
}

// OSBackend serves a root directory through the host filesystem while enforcing
// symlink-aware path confinement.
type OSBackend struct {
	root string
}

func NewOSBackend(root string) (*OSBackend, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil, errors.New("filebackend: root is required")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("filebackend: resolve root: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return nil, fmt.Errorf("filebackend: validate root: %w", err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return nil, fmt.Errorf("filebackend: stat root: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("filebackend: root is not a directory: %s", resolved)
	}
	return &OSBackend{root: resolved}, nil
}

func (b *OSBackend) Name() string { return "os" }
func (b *OSBackend) Root() string {
	if b == nil {
		return ""
	}
	return b.root
}

func (b *OSBackend) Resolve(relative string) (string, error) {
	if b == nil || b.root == "" {
		return "", errors.New("filebackend: incomplete OS backend")
	}
	raw := strings.TrimSpace(relative)
	if raw != "" && (strings.HasPrefix(raw, "/") || strings.Contains(raw, "\\") || strings.IndexByte(raw, 0) >= 0) {
		return "", ErrPathEscape
	}
	clean := filepath.Clean(filepath.FromSlash(raw))
	if clean == "." {
		clean = ""
	}
	if clean != "" {
		if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return "", ErrPathEscape
		}
	}
	joined := filepath.Join(b.root, clean)
	resolved, err := filepath.EvalSymlinks(joined)
	if err != nil {
		if os.IsNotExist(err) {
			parent := filepath.Dir(joined)
			resolvedParent, parentErr := filepath.EvalSymlinks(parent)
			if parentErr != nil {
				return "", fmt.Errorf("filebackend: resolve parent: %w", parentErr)
			}
			if !withinRoot(b.root, resolvedParent) {
				return "", ErrPathEscape
			}
			return filepath.Join(resolvedParent, filepath.Base(joined)), nil
		}
		return "", err
	}
	if !withinRoot(b.root, resolved) {
		return "", ErrPathEscape
	}
	return resolved, nil
}

func (b *OSBackend) Stat(path string) (os.FileInfo, error) { return os.Stat(path) }
func (b *OSBackend) Lstat(path string) (os.FileInfo, error) { return os.Lstat(path) }
func (b *OSBackend) ReadDir(path string) ([]os.DirEntry, error) { return os.ReadDir(path) }
func (b *OSBackend) Open(path string) (File, error) { return os.Open(path) }
func (b *OSBackend) OpenFile(path string, flag int, perm os.FileMode) (File, error) {
	return os.OpenFile(path, flag, perm)
}
func (b *OSBackend) Truncate(path string, size int64) error { return os.Truncate(path, size) }
func (b *OSBackend) Mkdir(path string, perm os.FileMode) error { return os.Mkdir(path, perm) }
func (b *OSBackend) Remove(path string) error { return os.Remove(path) }
func (b *OSBackend) Rename(oldPath, newPath string) error { return os.Rename(oldPath, newPath) }

var ErrPathEscape = errors.New("filebackend: path escapes export root")

func withinRoot(root, target string) bool {
	relative, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	return relative == "." || relative == "" || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative))
}
