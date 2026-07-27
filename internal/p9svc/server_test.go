package p9svc

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestServerServesFileReadOnlyOver9P(t *testing.T) {
	root := t.TempDir()
	want := []byte("hello from wv-9p\n")
	if err := os.WriteFile(filepath.Join(root, "hello.txt"), want, 0o644); err != nil {
		t.Fatal(err)
	}
	addr, stop := startTestServer(t, root)
	defer stop()

	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := &test9PClient{t: t, conn: conn, tag: 1}
	client.version("9P2000.L")
	client.attach(1)
	client.walk(1, 2, "hello.txt")
	client.open(2, 0)
	got := client.read(2, 0, 1024)
	if !bytes.Equal(got, want) {
		t.Fatalf("read bytes = %q, want %q", got, want)
	}
	client.clunk(2)
	client.clunk(1)
}

func TestServerListsDirectoryAndStats(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "b.txt"), []byte("b"), 0o644); err != nil {
		t.Fatal(err)
	}
	addr, stop := startTestServer(t, root)
	defer stop()

	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := &test9PClient{t: t, conn: conn, tag: 1}
	client.version("9P2000")
	client.attach(1)
	client.open(1, 0)
	dirData := string(client.read(1, 0, 4096))
	if !strings.Contains(dirData, "a.txt") || !strings.Contains(dirData, "b.txt") {
		t.Fatalf("directory stat payload missing entries: %q", dirData)
	}
	stat := client.stat(1)
	if !strings.Contains(string(stat), "/") {
		t.Fatalf("root stat payload missing root name: %q", string(stat))
	}
}

func TestServerRejectsWriteOpenAndPathEscape(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "hello.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	addr, stop := startTestServer(t, root)
	defer stop()

	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := &test9PClient{t: t, conn: conn, tag: 1}
	client.version("9P2000.u")
	client.attach(1)
	client.walk(1, 2, "hello.txt")
	client.expectError(Topen, client.nextTag(), packOpen(2, 1), "read_only")
	client.expectError(Twalk, client.nextTag(), packWalk(1, 3, ".."), "invalid_walk_name")
}

func startTestServer(t *testing.T, root string) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	errCh := make(chan error, 1)
	go func() { errCh <- ServeForTest(root, ln) }()
	addr := ln.Addr().String()
	if !WaitForPort(addr, time.Second) {
		t.Fatalf("server did not open %s", addr)
	}
	return addr, func() {
		_ = ln.Close()
		select {
		case <-errCh:
		case <-time.After(time.Second):
			t.Fatalf("server did not stop")
		}
	}
}

type test9PClient struct {
	t    *testing.T
	conn net.Conn
	tag  uint16
}

func (c *test9PClient) nextTag() uint16 {
	tag := c.tag
	c.tag++
	return tag
}

func (c *test9PClient) version(version string) {
	var p bytes.Buffer
	_ = binary.Write(&p, binary.LittleEndian, uint32(8192))
	packString(&p, version)
	payload := c.send(Tversion, Rversion, c.nextTag(), p.Bytes())
	got, _, err := unpackString(payload, 4)
	if err != nil {
		c.t.Fatal(err)
	}
	if got == "unknown" {
		c.t.Fatalf("version %q rejected", version)
	}
}

func (c *test9PClient) attach(fid uint32) {
	var p bytes.Buffer
	_ = binary.Write(&p, binary.LittleEndian, fid)
	_ = binary.Write(&p, binary.LittleEndian, uint32(^uint32(0)))
	packString(&p, "tester")
	packString(&p, "")
	_ = binary.Write(&p, binary.LittleEndian, uint32(0))
	_ = c.send(Tattach, Rattach, c.nextTag(), p.Bytes())
}

func (c *test9PClient) walk(fid, newfid uint32, names ...string) {
	payload := c.send(Twalk, Rwalk, c.nextTag(), packWalk(fid, newfid, names...))
	got := int(binary.LittleEndian.Uint16(payload[:2]))
	if got != len(names) {
		c.t.Fatalf("walk qids=%d, want %d", got, len(names))
	}
}

func (c *test9PClient) open(fid uint32, mode uint8) {
	_ = c.send(Topen, Ropen, c.nextTag(), packOpen(fid, mode))
}

func (c *test9PClient) read(fid uint32, offset uint64, count uint32) []byte {
	var p bytes.Buffer
	_ = binary.Write(&p, binary.LittleEndian, fid)
	_ = binary.Write(&p, binary.LittleEndian, offset)
	_ = binary.Write(&p, binary.LittleEndian, count)
	payload := c.send(Tread, Rread, c.nextTag(), p.Bytes())
	n := int(binary.LittleEndian.Uint32(payload[:4]))
	return payload[4 : 4+n]
}

func (c *test9PClient) stat(fid uint32) []byte {
	var p bytes.Buffer
	_ = binary.Write(&p, binary.LittleEndian, fid)
	return c.send(Tstat, Rstat, c.nextTag(), p.Bytes())
}

func (c *test9PClient) clunk(fid uint32) {
	var p bytes.Buffer
	_ = binary.Write(&p, binary.LittleEndian, fid)
	_ = c.send(Tclunk, Rclunk, c.nextTag(), p.Bytes())
}

func (c *test9PClient) send(req, expect uint8, tag uint16, payload []byte) []byte {
	c.t.Helper()
	if err := writeMessage(c.conn, req, tag, payload); err != nil {
		c.t.Fatal(err)
	}
	msg, err := readMessage(c.conn)
	if err != nil {
		c.t.Fatal(err)
	}
	if msg.Type == Rerror {
		errText, _, _ := unpackString(msg.Payload, 0)
		c.t.Fatalf("unexpected Rerror: %s", errText)
	}
	if msg.Tag != tag || msg.Type != expect {
		c.t.Fatalf("response type/tag=(%d,%d), want (%d,%d)", msg.Type, msg.Tag, expect, tag)
	}
	return msg.Payload
}

func (c *test9PClient) expectError(req uint8, tag uint16, payload []byte, want string) {
	c.t.Helper()
	if err := writeMessage(c.conn, req, tag, payload); err != nil {
		c.t.Fatal(err)
	}
	msg, err := readMessage(c.conn)
	if err != nil {
		c.t.Fatal(err)
	}
	if msg.Type != Rerror {
		c.t.Fatalf("response type=%d, want Rerror", msg.Type)
	}
	got, _, _ := unpackString(msg.Payload, 0)
	if !strings.Contains(got, want) {
		c.t.Fatalf("Rerror=%q, want substring %q", got, want)
	}
}

func packWalk(fid, newfid uint32, names ...string) []byte {
	var p bytes.Buffer
	_ = binary.Write(&p, binary.LittleEndian, fid)
	_ = binary.Write(&p, binary.LittleEndian, newfid)
	_ = binary.Write(&p, binary.LittleEndian, uint16(len(names)))
	for _, name := range names {
		packString(&p, name)
	}
	return p.Bytes()
}

func packOpen(fid uint32, mode uint8) []byte {
	var p bytes.Buffer
	_ = binary.Write(&p, binary.LittleEndian, fid)
	p.WriteByte(mode)
	return p.Bytes()
}
