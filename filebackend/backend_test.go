package filebackend

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestOSBackendConfinesPaths(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "inside.txt"), []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	backend, err := NewOSBackend(root)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := backend.Resolve("inside.txt")
	if err != nil {
		t.Fatal(err)
	}
	if resolved != filepath.Join(root, "inside.txt") {
		t.Fatalf("resolved=%q", resolved)
	}
	for _, invalid := range []string{"../outside", "/absolute", `dir\file`, "bad\x00path"} {
		if _, err := backend.Resolve(invalid); !errors.Is(err, ErrPathEscape) {
			t.Fatalf("path=%q error=%v want ErrPathEscape", invalid, err)
		}
	}
}

func TestOSBackendRejectsSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation may require elevated privileges")
	}
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	backend, err := NewOSBackend(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backend.Resolve("escape"); !errors.Is(err, ErrPathEscape) {
		t.Fatalf("error=%v want ErrPathEscape", err)
	}
	if _, err := backend.Resolve("escape/new.txt"); err == nil {
		t.Fatal("expected path escape rejection for missing child below external symlink")
	}
}
