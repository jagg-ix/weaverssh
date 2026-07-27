package p9client

import (
	"net"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"weaverssh/internal/p9svc"
)

// startServer spins up an in-process p9svc on a random port and returns its
// address. The listener closes when the test finishes.
func startServer(t *testing.T, root string, readOnly bool) string {
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
	return ln.Addr().String()
}

func dial(t *testing.T, addr string) *Client {
	t.Helper()
	c, err := Dial(addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestReadListAndStat(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("alpha"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sub", "b.txt"), []byte("bravo!!"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := dial(t, startServer(t, root, true))

	entries, err := c.List("")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	if len(entries) != 2 || entries[0].Name != "a.txt" || entries[1].Name != "sub" || !entries[1].IsDir {
		t.Fatalf("unexpected listing: %+v", entries)
	}
	if entries[0].Size != 5 {
		t.Fatalf("size of a.txt = %d, want 5", entries[0].Size)
	}

	data, err := c.ReadFile("sub/b.txt")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "bravo!!" {
		t.Fatalf("ReadFile = %q, want %q", data, "bravo!!")
	}

	st, err := c.Stat("sub")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if !st.IsDir || st.Name != "sub" {
		t.Fatalf("Stat sub = %+v", st)
	}
}

func TestWriteCreateMkdirRemove(t *testing.T) {
	root := t.TempDir()
	c := dial(t, startServer(t, root, false))

	if err := c.Mkdir("region-a"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	payload := []byte("pushed payload\n")
	if err := c.WriteFile("region-a/up.txt", payload); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// Landed on the real filesystem, not staged anywhere.
	got, err := os.ReadFile(filepath.Join(root, "region-a", "up.txt"))
	if err != nil {
		t.Fatalf("server-side read: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("server file = %q, want %q", got, payload)
	}

	// Overwrite (OTRUNC) shrinks the file correctly.
	if err := c.WriteFile("region-a/up.txt", []byte("x")); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	rd, err := c.ReadFile("region-a/up.txt")
	if err != nil || string(rd) != "x" {
		t.Fatalf("after overwrite ReadFile=%q err=%v", rd, err)
	}

	// MkdirAll creates intermediate parents.
	if err := c.MkdirAll("a/b/c"); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if st, err := c.Stat("a/b/c"); err != nil || !st.IsDir {
		t.Fatalf("MkdirAll Stat: %+v err=%v", st, err)
	}

	if err := c.Remove("region-a/up.txt"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "region-a", "up.txt")); !os.IsNotExist(err) {
		t.Fatalf("file still present after Remove (err=%v)", err)
	}
}

func TestFileOffsetIO(t *testing.T) {
	root := t.TempDir()
	c := dial(t, startServer(t, root, false))

	if err := c.Mkdir("data"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	// CreateFile then positional writes that cross the msize chunk boundary.
	f, err := c.CreateFile("data/blob.bin", 0o644)
	if err != nil {
		t.Fatalf("CreateFile: %v", err)
	}
	big := make([]byte, 150*1024)
	for i := range big {
		big[i] = byte(i * 7)
	}
	if n, err := f.WriteAt(big, 0); err != nil || n != len(big) {
		t.Fatalf("WriteAt: n=%d err=%v", n, err)
	}
	// Overwrite a slice far from the start.
	if _, err := f.WriteAt([]byte("MARKER"), 100*1024); err != nil {
		t.Fatalf("WriteAt marker: %v", err)
	}
	_ = f.Close()

	// Positional reads via a fresh open.
	rf, err := c.OpenFile("data/blob.bin", OREAD)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer rf.Close()
	mark := make([]byte, 6)
	if n, err := rf.ReadAt(mark, 100*1024); err != nil || string(mark[:n]) != "MARKER" {
		t.Fatalf("ReadAt marker: %q n=%d err=%v", mark[:n], n, err)
	}
	// Read spanning the chunk boundary returns the original bytes.
	span := make([]byte, 80*1024)
	n, err := rf.ReadAt(span, 0)
	if err != nil || n != len(span) {
		t.Fatalf("ReadAt span: n=%d err=%v", n, err)
	}
	for i := 0; i < len(span); i++ {
		if i >= 100*1024 { // past the marker region, not relevant here
			break
		}
		if span[i] != byte(i*7) {
			t.Fatalf("byte %d = %d, want %d", i, span[i], byte(i*7))
		}
	}
	// Short read at EOF.
	tail := make([]byte, 1024)
	if n, _ := rf.ReadAt(tail, int64(len(big))); n != 0 {
		t.Fatalf("ReadAt at EOF returned %d bytes, want 0", n)
	}
}

func TestReadOnlyServerRejectsWrites(t *testing.T) {
	root := t.TempDir()
	c := dial(t, startServer(t, root, true))

	if err := c.Mkdir("nope"); err == nil {
		t.Fatal("Mkdir succeeded on read-only server")
	}
	if err := c.WriteFile("nope.txt", []byte("data")); err == nil {
		t.Fatal("WriteFile succeeded on read-only server")
	}
	if _, err := os.Stat(filepath.Join(root, "nope")); !os.IsNotExist(err) {
		t.Fatalf("read-only server created a directory")
	}
}

func TestLargeFileRoundTrip(t *testing.T) {
	root := t.TempDir()
	c := dial(t, startServer(t, root, false))
	// Larger than msize to exercise chunked read/write.
	big := make([]byte, 200*1024)
	for i := range big {
		big[i] = byte(i % 251)
	}
	if err := c.WriteFile("big.bin", big); err != nil {
		t.Fatalf("WriteFile big: %v", err)
	}
	got, err := c.ReadFile("big.bin")
	if err != nil {
		t.Fatalf("ReadFile big: %v", err)
	}
	if len(got) != len(big) {
		t.Fatalf("length mismatch got=%d want=%d", len(got), len(big))
	}
	for i := range big {
		if got[i] != big[i] {
			t.Fatalf("byte %d differs: got %d want %d", i, got[i], big[i])
		}
	}
}
