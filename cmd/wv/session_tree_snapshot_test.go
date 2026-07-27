package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVerifyLocalEntryUnchangedDetectsReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source.bin")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	original, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyLocalEntryUnchanged(path, original); err != nil {
		t.Fatalf("unchanged source rejected: %v", err)
	}
	replacement := filepath.Join(filepath.Dir(path), "replacement.bin")
	if err := os.WriteFile(replacement, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(replacement, original.ModTime(), original.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if err := verifyLocalEntryUnchanged(path, original); err == nil {
		t.Fatal("replacement with matching size and mtime was accepted")
	}
}

func TestVerifyLocalEntryUnchangedDetectsMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source.bin")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	original, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond)
	if err := os.WriteFile(path, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyLocalEntryUnchanged(path, original); err == nil {
		t.Fatal("mutated source was accepted")
	}
}

func TestVerifyLocalSymlinkUnchanged(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "a"), []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "b"), []byte("b"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink("a", link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := verifyLocalSymlinkUnchanged(link, "a"); err != nil {
		t.Fatalf("unchanged symlink rejected: %v", err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("b", link); err != nil {
		t.Fatal(err)
	}
	if err := verifyLocalSymlinkUnchanged(link, "a"); err == nil {
		t.Fatal("changed symlink target was accepted")
	}
}
