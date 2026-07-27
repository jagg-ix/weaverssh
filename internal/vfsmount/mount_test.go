//go:build linux || darwin

package vfsmount

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"weaverssh/internal/p9client"
	"weaverssh/internal/p9svc"
	"weaverssh/internal/vfs"
)

func newClient(t *testing.T, root string, readOnly bool) *p9client.Client {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv, err := p9svc.New(p9svc.Config{Root: root, Addr: ln.Addr().String(), ReadOnly: readOnly})
	if err != nil {
		t.Fatalf("p9svc.New: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = ln.Close() })
	c, err := p9client.Dial(ln.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestHandleReadWriteFlush exercises the buffering/offset translation that the
// FUSE Open/Read/Write/Flush methods perform, against a live 9P server. (The
// kernel mount path is validated separately; CI/sandbox lacks FUSE+TCC access.)
func TestHandleReadWriteFlush(t *testing.T) {
	root := t.TempDir()
	c := newClient(t, root, false)
	if err := c.WriteFile("file.txt", []byte("0123456789")); err != nil {
		t.Fatalf("seed: %v", err)
	}
	ctx := context.Background()
	n := &node{client: c, rel: "file.txt", isDir: false, readOnly: false}

	fh, _, errno := n.Open(ctx, uint32(syscall.O_RDWR))
	if errno != 0 {
		t.Fatalf("Open errno=%v", errno)
	}
	defer n.Release(ctx, fh)

	// Read a middle slice at an offset.
	dst := make([]byte, 4)
	rr, errno := n.Read(ctx, fh, dst, 3)
	if errno != 0 {
		t.Fatalf("Read errno=%v", errno)
	}
	got, st := rr.Bytes(dst)
	if !st.Ok() || string(got) != "3456" {
		t.Fatalf("Read at off=3 got %q status %v", got, st)
	}

	// Overwrite at an offset, then extend past EOF.
	if w, errno := n.Write(ctx, fh, []byte("AB"), 1); errno != 0 || w != 2 {
		t.Fatalf("Write mid: w=%d errno=%v", w, errno)
	}
	if w, errno := n.Write(ctx, fh, []byte("XY"), 10); errno != 0 || w != 2 {
		t.Fatalf("Write extend: w=%d errno=%v", w, errno)
	}
	if errno := n.Flush(ctx, fh); errno != 0 {
		t.Fatalf("Flush errno=%v", errno)
	}

	// The server-side file must reflect the positional writes (write-through).
	out, err := c.ReadFile("file.txt")
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(out) != "0AB3456789XY" {
		t.Fatalf("after flush = %q, want %q", out, "0AB3456789XY")
	}
}

func TestReadOnlyHandleRejectsWrite(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "ro.txt"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := newClient(t, root, true)
	n := &node{client: c, rel: "ro.txt", isDir: false, readOnly: true}
	if _, errno := n.Write(context.Background(), &handle{node: n}, []byte("x"), 0); errno != syscall.EROFS {
		t.Fatalf("read-only Write errno=%v, want EROFS", errno)
	}
	if _, _, errno := n.Open(context.Background(), uint32(syscall.O_WRONLY)); errno != syscall.EROFS {
		t.Fatalf("read-only Open(O_WRONLY) errno=%v, want EROFS", errno)
	}
}

func TestPureHelpers(t *testing.T) {
	root := (&node{rel: ""}).child("a")
	if root != "a" {
		t.Fatalf("child of root = %q", root)
	}
	if sub := (&node{rel: "a/b"}).child("c"); sub != "a/b/c" {
		t.Fatalf("nested child = %q", sub)
	}
	if fileMode(true) != (fuse.S_IFDIR | 0o755) {
		t.Fatalf("dir mode wrong")
	}
	if fileMode(false) != (fuse.S_IFREG | 0o644) {
		t.Fatalf("file mode wrong")
	}
	for _, f := range []uint32{uint32(syscall.O_WRONLY), uint32(syscall.O_RDWR), uint32(syscall.O_TRUNC)} {
		if _, write := openMode(f); !write {
			t.Fatalf("openMode(%d) write=false, want true", f)
		}
	}
	if _, write := openMode(uint32(syscall.O_RDONLY)); write {
		t.Fatalf("openMode(O_RDONLY) write=true, want false")
	}
	if m, _ := openMode(uint32(syscall.O_WRONLY | syscall.O_TRUNC)); m != (p9client.OWRITE | p9client.OTRUNC) {
		t.Fatalf("openMode(O_WRONLY|O_TRUNC) mode=%d, want OWRITE|OTRUNC", m)
	}
	if m, _ := openMode(uint32(syscall.O_RDONLY)); m != p9client.OREAD {
		t.Fatalf("openMode(O_RDONLY) mode=%d, want OREAD", m)
	}
}

func TestAttrCache(t *testing.T) {
	c := &attrCache{ttl: time.Minute, stat: map[string]statEntry{}, list: map[string]listEntry{}}
	c.putStat("a/b", p9client.DirEntry{Name: "b", Size: 7})
	if e, ok := c.getStat("a/b"); !ok || e.Size != 7 {
		t.Fatalf("getStat miss: %+v ok=%v", e, ok)
	}
	c.putList("a", []p9client.DirEntry{{Name: "b"}})
	if _, ok := c.getList("a"); !ok {
		t.Fatal("getList miss")
	}
	// Mutating a/b drops its stat and the parent listing.
	c.invalidate("a/b")
	if _, ok := c.getStat("a/b"); ok {
		t.Fatal("stat not invalidated")
	}
	if _, ok := c.getList("a"); ok {
		t.Fatal("parent listing not invalidated")
	}
	// A disabled (zero-TTL or nil) cache never hits.
	var nilCache *attrCache
	nilCache.putStat("x", p9client.DirEntry{})
	if _, ok := nilCache.getStat("x"); ok {
		t.Fatal("nil cache should not hit")
	}
	off := &attrCache{ttl: 0, stat: map[string]statEntry{}, list: map[string]listEntry{}}
	off.putStat("x", p9client.DirEntry{Name: "x"})
	if _, ok := off.getStat("x"); ok {
		t.Fatal("zero-ttl cache should not hit")
	}
}

func TestViewProjectionReaddirLookupAndHiddenPaths(t *testing.T) {
	root := t.TempDir()
	mustMkdirAll(t, filepath.Join(root, "docs", "api"))
	mustMkdirAll(t, filepath.Join(root, "docs", "private"))
	mustMkdirAll(t, filepath.Join(root, "docs", ".git"))
	mustWrite(t, filepath.Join(root, "docs", "api", "readme.md"), "visible\n")
	mustWrite(t, filepath.Join(root, "docs", "private", "secret.txt"), "hidden\n")
	mustWrite(t, filepath.Join(root, "docs", ".git", "config"), "hidden\n")

	c := newClient(t, root, false)
	view := sampleMountView()
	n := &node{
		client:   c,
		rel:      "",
		viewRel:  "",
		isDir:    true,
		readOnly: false,
		cache:    &attrCache{ttl: time.Minute, stat: map[string]statEntry{}, list: map[string]listEntry{}},
		view:     view,
	}

	ds, errno := n.Readdir(context.Background())
	if errno != 0 {
		t.Fatalf("Readdir errno=%v", errno)
	}
	entries := drainDirStream(t, ds)
	if len(entries) != 1 || entries[0] != "Documentation" {
		t.Fatalf("root entries=%v, want [Documentation]", entries)
	}

	docNode, _, errno := n.lookupChild("Documentation")
	if errno != 0 || docNode == nil {
		t.Fatalf("lookupChild Documentation errno=%v node nil=%v", errno, docNode == nil)
	}
	if docNode.rel != "docs" || docNode.viewPath() != "Documentation" {
		t.Fatalf("doc node rel=%q view=%q, want docs/Documentation", docNode.rel, docNode.viewPath())
	}

	ds, errno = docNode.Readdir(context.Background())
	if errno != 0 {
		t.Fatalf("doc Readdir errno=%v", errno)
	}
	entries = drainDirStream(t, ds)
	if len(entries) != 1 || entries[0] != "api" {
		t.Fatalf("doc entries=%v, want [api]", entries)
	}
	if _, _, errno := docNode.lookupChild("private"); errno != syscall.ENOENT {
		t.Fatalf("hidden private lookupChild errno=%v, want ENOENT", errno)
	}
	if _, _, errno := docNode.lookupChild(".git"); errno != syscall.ENOENT {
		t.Fatalf("hidden .git lookupChild errno=%v, want ENOENT", errno)
	}
}

func TestViewProjectionWritesThroughRenameAndRejectsHidden(t *testing.T) {
	root := t.TempDir()
	mustMkdirAll(t, filepath.Join(root, "docs"))
	mustMkdirAll(t, filepath.Join(root, "docs", "private"))
	c := newClient(t, root, false)
	n := &node{
		client:   c,
		rel:      "docs",
		viewRel:  "Documentation",
		isDir:    true,
		readOnly: false,
		cache:    &attrCache{ttl: time.Minute, stat: map[string]statEntry{}, list: map[string]listEntry{}},
		view:     sampleMountView(),
	}

	child, file, errno := n.createFile("note.txt")
	if errno != 0 {
		t.Fatalf("createFile visible note errno=%v", errno)
	}
	fh := &handle{node: child, file: file}
	if w, errno := child.Write(context.Background(), fh, []byte("hello"), 0); errno != 0 || w != 5 {
		t.Fatalf("Write visible note w=%d errno=%v", w, errno)
	}
	_ = child.Release(context.Background(), fh)
	got, err := os.ReadFile(filepath.Join(root, "docs", "note.txt"))
	if err != nil || string(got) != "hello" {
		t.Fatalf("source write got=%q err=%v, want hello", got, err)
	}

	private := &node{client: c, rel: "docs/private", viewRel: "Documentation/private", isDir: true, readOnly: false, cache: n.cache, view: sampleMountView()}
	if _, _, errno := private.createFile("secret.txt"); errno != syscall.EACCES {
		t.Fatalf("hidden createFile errno=%v, want EACCES", errno)
	}
	if errno := n.remove("private"); errno != syscall.EACCES {
		t.Fatalf("hidden remove errno=%v, want EACCES", errno)
	}
}

func sampleMountView() vfs.ViewConfig {
	return vfs.ViewConfig{Version: vfs.ViewVersion, Rules: []vfs.ViewRule{
		{Action: vfs.ViewActionHide, Match: ".git"},
		{Action: vfs.ViewActionHide, Match: "docs/private"},
		{Action: vfs.ViewActionRename, Match: "docs", To: "Documentation"},
	}}
}

func drainDirStream(t *testing.T, ds fs.DirStream) []string {
	t.Helper()
	var out []string
	for ds.HasNext() {
		e, errno := ds.Next()
		if errno != 0 {
			t.Fatalf("DirStream Next errno=%v", errno)
		}
		out = append(out, e.Name)
	}
	return out
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}
