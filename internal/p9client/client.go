// Package p9client is a minimal synchronous 9P2000 client that speaks the same
// dialect served by internal/p9svc. It backs the vfs:// command-line tools
// (wls/wcp/wmkdir/wtool) so files move endpoint-to-endpoint over the tunnel
// without staging on any intermediary hop.
package p9client

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// 9P2000 message types (must match internal/p9svc).
const (
	tVersion uint8 = 100
	rVersion uint8 = 101
	rError   uint8 = 107
	tAttach  uint8 = 104
	rAttach  uint8 = 105
	tWalk    uint8 = 110
	rWalk    uint8 = 111
	tOpen    uint8 = 112
	rOpen    uint8 = 113
	tCreate  uint8 = 114
	rCreate  uint8 = 115
	tRead    uint8 = 116
	rRead    uint8 = 117
	tWrite   uint8 = 118
	rWrite   uint8 = 119
	tClunk   uint8 = 120
	rClunk   uint8 = 121
	tRemove  uint8 = 122
	rRemove  uint8 = 123
	tStat    uint8 = 124
	rStat    uint8 = 125
)

// Open modes / perm bits.
const (
	OREAD  uint8 = 0x00
	OWRITE uint8 = 0x01
	OTRUNC uint8 = 0x10

	permDir uint32 = 0x80000000 // DMDIR
	nofid   uint32 = ^uint32(0)
)

const defaultMsize uint32 = 65536

// Client is a connected 9P session attached at the served root. It is safe for
// concurrent use: each request/response exchange holds mu, so a FUSE mount can
// drive many in-flight syscalls over the single connection.
type Client struct {
	mu      sync.Mutex
	conn    net.Conn
	msize   uint32
	tag     uint16
	nextFid uint32
	rootFid uint32
}

// DirEntry is one listing entry decoded from a directory read.
type DirEntry struct {
	Name  string
	IsDir bool
	Size  uint64
}

// Dial connects directly to a 9P endpoint (e.g. a tunnel-forwarded port).
func Dial(addr string, timeout time.Duration) (*Client, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	return attach(conn)
}

// DialSOCKS connects to a 9P endpoint through a SOCKS5 proxy — the path used
// when the 9P service is reachable only via the weaverssh SOCKS tunnel.
func DialSOCKS(socksAddr, addr string, timeout time.Duration) (*Client, error) {
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, &net.Dialer{Timeout: timeout})
	if err != nil {
		return nil, fmt.Errorf("socks5 %s: %w", socksAddr, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cd, ok := dialer.(proxy.ContextDialer)
	var conn net.Conn
	if ok {
		conn, err = cd.DialContext(ctx, "tcp", addr)
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("dial %s via socks %s: %w", addr, socksAddr, err)
	}
	return attach(conn)
}

func attach(conn net.Conn) (*Client, error) {
	c := &Client{conn: conn, msize: defaultMsize, nextFid: 1, rootFid: 0}
	if err := c.version(); err != nil {
		conn.Close()
		return nil, err
	}
	if err := c.attachRoot(); err != nil {
		conn.Close()
		return nil, err
	}
	return c, nil
}

// Close clunks the root fid and closes the connection.
func (c *Client) Close() error {
	_ = c.clunk(c.rootFid)
	return c.conn.Close()
}

func (c *Client) version() error {
	var p bytes.Buffer
	_ = binary.Write(&p, binary.LittleEndian, c.msize)
	packString(&p, "9P2000")
	resp, err := c.rpc(tVersion, p.Bytes())
	if err != nil {
		return err
	}
	if len(resp) < 4 {
		return fmt.Errorf("short_rversion")
	}
	if m := binary.LittleEndian.Uint32(resp[:4]); m > 0 && m < c.msize {
		c.msize = m
	}
	return nil
}

func (c *Client) attachRoot() error {
	var p bytes.Buffer
	_ = binary.Write(&p, binary.LittleEndian, c.rootFid)
	_ = binary.Write(&p, binary.LittleEndian, nofid) // afid
	packString(&p, "weaverssh")                      // uname
	packString(&p, "")                               // aname
	_, err := c.rpc(tAttach, p.Bytes())
	return err
}

func (c *Client) allocFid() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	f := c.nextFid
	c.nextFid++
	return f
}

// walk creates a fresh fid pointing at path (slash-separated, relative to root).
// The caller owns the returned fid and must clunk it.
func (c *Client) walk(path string) (uint32, error) {
	names := splitPath(path)
	newfid := c.allocFid()
	var p bytes.Buffer
	_ = binary.Write(&p, binary.LittleEndian, c.rootFid)
	_ = binary.Write(&p, binary.LittleEndian, newfid)
	_ = binary.Write(&p, binary.LittleEndian, uint16(len(names)))
	for _, n := range names {
		packString(&p, n)
	}
	if _, err := c.rpc(tWalk, p.Bytes()); err != nil {
		return 0, err
	}
	return newfid, nil
}

func (c *Client) open(fid uint32, mode uint8) error {
	var p bytes.Buffer
	_ = binary.Write(&p, binary.LittleEndian, fid)
	p.WriteByte(mode)
	_, err := c.rpc(tOpen, p.Bytes())
	return err
}

func (c *Client) create(dirFid uint32, name string, perm uint32, mode uint8) error {
	var p bytes.Buffer
	_ = binary.Write(&p, binary.LittleEndian, dirFid)
	packString(&p, name)
	_ = binary.Write(&p, binary.LittleEndian, perm)
	p.WriteByte(mode)
	_, err := c.rpc(tCreate, p.Bytes())
	return err
}

func (c *Client) clunk(fid uint32) error {
	var p bytes.Buffer
	_ = binary.Write(&p, binary.LittleEndian, fid)
	_, err := c.rpc(tClunk, p.Bytes())
	return err
}

func (c *Client) remove(fid uint32) error {
	var p bytes.Buffer
	_ = binary.Write(&p, binary.LittleEndian, fid)
	_, err := c.rpc(tRemove, p.Bytes())
	return err
}

// --- high-level operations -------------------------------------------------

// List returns the entries of the directory at path.
func (c *Client) List(path string) ([]DirEntry, error) {
	fid, err := c.walk(path)
	if err != nil {
		return nil, err
	}
	defer c.clunk(fid)
	if err := c.open(fid, OREAD); err != nil {
		return nil, err
	}
	data, err := c.readAll(fid)
	if err != nil {
		return nil, err
	}
	var entries []DirEntry
	off := 0
	for off < len(data) {
		e, next, err := parseStat(data, off)
		if err != nil {
			return nil, err
		}
		off = next
		entries = append(entries, e)
	}
	return entries, nil
}

// Stat returns metadata for a single path.
func (c *Client) Stat(path string) (DirEntry, error) {
	fid, err := c.walk(path)
	if err != nil {
		return DirEntry{}, err
	}
	defer c.clunk(fid)
	var p bytes.Buffer
	_ = binary.Write(&p, binary.LittleEndian, fid)
	resp, err := c.rpc(tStat, p.Bytes())
	if err != nil {
		return DirEntry{}, err
	}
	if len(resp) < 2 {
		return DirEntry{}, fmt.Errorf("short_rstat")
	}
	e, _, err := parseStat(resp, 2) // skip the outer stat_len[2]
	return e, err
}

// ReadFile reads the whole file at path.
func (c *Client) ReadFile(path string) ([]byte, error) {
	fid, err := c.walk(path)
	if err != nil {
		return nil, err
	}
	defer c.clunk(fid)
	if err := c.open(fid, OREAD); err != nil {
		return nil, err
	}
	return c.readAll(fid)
}

func (c *Client) readAll(fid uint32) ([]byte, error) {
	var out bytes.Buffer
	var offset uint64
	chunk := c.msize - 11 // leave room for Rread header+count
	if chunk == 0 || chunk > 1<<20 {
		chunk = 8192
	}
	for {
		var p bytes.Buffer
		_ = binary.Write(&p, binary.LittleEndian, fid)
		_ = binary.Write(&p, binary.LittleEndian, offset)
		_ = binary.Write(&p, binary.LittleEndian, chunk)
		resp, err := c.rpc(tRead, p.Bytes())
		if err != nil {
			return nil, err
		}
		if len(resp) < 4 {
			return nil, fmt.Errorf("short_rread")
		}
		n := binary.LittleEndian.Uint32(resp[:4])
		if n == 0 {
			break
		}
		if int(n) > len(resp)-4 {
			n = uint32(len(resp) - 4)
		}
		out.Write(resp[4 : 4+int(n)])
		offset += uint64(n)
	}
	return out.Bytes(), nil
}

// WriteFile creates or truncates path and writes data. The parent directory
// must already exist.
func (c *Client) WriteFile(path string, data []byte) error {
	dir, name := splitParent(path)
	if name == "" {
		return fmt.Errorf("invalid_path %q", path)
	}
	parent, err := c.walk(dir)
	if err != nil {
		return fmt.Errorf("walk parent %q: %w", dir, err)
	}
	defer c.clunk(parent)

	// Use the existing file if present, else create it. Tcreate rebinds the
	// fid to the new file, so write through the same fid in both branches.
	if child, werr := c.walk(path); werr == nil {
		defer c.clunk(child)
		if err := c.open(child, OWRITE|OTRUNC); err != nil {
			return err
		}
		return c.writeAll(child, data)
	}
	if err := c.create(parent, name, 0o644, OWRITE|OTRUNC); err != nil {
		return err
	}
	return c.writeAll(parent, data)
}

func (c *Client) writeAll(fid uint32, data []byte) error {
	chunk := int(c.msize) - 23 // header(7)+fid(4)+offset(8)+count(4)
	if chunk <= 0 || chunk > 1<<20 {
		chunk = 8192
	}
	var offset uint64
	for len(data) > 0 {
		n := len(data)
		if n > chunk {
			n = chunk
		}
		var p bytes.Buffer
		_ = binary.Write(&p, binary.LittleEndian, fid)
		_ = binary.Write(&p, binary.LittleEndian, offset)
		_ = binary.Write(&p, binary.LittleEndian, uint32(n))
		p.Write(data[:n])
		resp, err := c.rpc(tWrite, p.Bytes())
		if err != nil {
			return err
		}
		if len(resp) < 4 {
			return fmt.Errorf("short_rwrite")
		}
		wrote := int(binary.LittleEndian.Uint32(resp[:4]))
		if wrote <= 0 {
			return fmt.Errorf("write_made_no_progress")
		}
		if wrote > n {
			wrote = n
		}
		offset += uint64(wrote)
		data = data[wrote:]
	}
	return nil
}

// Mkdir creates a directory at path; the parent must already exist.
func (c *Client) Mkdir(path string) error {
	dir, name := splitParent(path)
	if name == "" {
		return fmt.Errorf("invalid_path %q", path)
	}
	parent, err := c.walk(dir)
	if err != nil {
		return fmt.Errorf("walk parent %q: %w", dir, err)
	}
	defer c.clunk(parent)
	return c.create(parent, name, permDir|0o755, OREAD)
}

// MkdirAll creates path and any missing parents.
func (c *Client) MkdirAll(path string) error {
	names := splitPath(path)
	cur := ""
	for _, n := range names {
		if cur == "" {
			cur = n
		} else {
			cur = cur + "/" + n
		}
		if _, err := c.walk(cur); err == nil {
			continue // already exists
		}
		if err := c.Mkdir(cur); err != nil {
			return err
		}
	}
	return nil
}

// Remove deletes a file or empty directory at path.
func (c *Client) Remove(path string) error {
	fid, err := c.walk(path)
	if err != nil {
		return err
	}
	return c.remove(fid) // Tremove clunks the fid server-side
}

// --- open file handles (offset I/O) ----------------------------------------

// File is an open 9P fid supporting positional reads/writes. It backs the FUSE
// mount, which streams ranges instead of buffering whole files. Close clunks
// the fid. A File is used serially per kernel file handle; the underlying
// Client serializes the actual RPCs.
type File struct {
	c   *Client
	fid uint32
}

// OpenFile walks to path and opens it with the given 9P mode (OREAD/OWRITE,
// optionally |OTRUNC). The caller must Close the returned File.
func (c *Client) OpenFile(path string, mode uint8) (*File, error) {
	fid, err := c.walk(path)
	if err != nil {
		return nil, err
	}
	if err := c.open(fid, mode); err != nil {
		_ = c.clunk(fid)
		return nil, err
	}
	return &File{c: c, fid: fid}, nil
}

// CreateFile creates (or truncates) path and returns it open for writing. The
// parent directory must exist.
func (c *Client) CreateFile(path string, perm uint32) (*File, error) {
	dir, name := splitParent(path)
	if name == "" {
		return nil, fmt.Errorf("invalid_path %q", path)
	}
	fid, err := c.walk(dir)
	if err != nil {
		return nil, fmt.Errorf("walk parent %q: %w", dir, err)
	}
	// Tcreate rebinds fid to the new file, leaving it open for writing.
	if err := c.create(fid, name, perm&0o777, OWRITE|OTRUNC); err != nil {
		_ = c.clunk(fid)
		return nil, err
	}
	return &File{c: c, fid: fid}, nil
}

// ReadAt fills p from offset off, issuing as many Tread calls as needed. It
// returns the number of bytes read; a short count means end of file.
func (f *File) ReadAt(p []byte, off int64) (int, error) {
	chunk := f.c.msize - 11 // Rread header + count
	if chunk == 0 || chunk > 1<<20 {
		chunk = 8192
	}
	total := 0
	for total < len(p) {
		want := uint32(len(p) - total)
		if want > chunk {
			want = chunk
		}
		var b bytes.Buffer
		_ = binary.Write(&b, binary.LittleEndian, f.fid)
		_ = binary.Write(&b, binary.LittleEndian, uint64(off)+uint64(total))
		_ = binary.Write(&b, binary.LittleEndian, want)
		resp, err := f.c.rpc(tRead, b.Bytes())
		if err != nil {
			return total, err
		}
		if len(resp) < 4 {
			return total, fmt.Errorf("short_rread")
		}
		n := binary.LittleEndian.Uint32(resp[:4])
		if n == 0 {
			break // EOF
		}
		if int(n) > len(resp)-4 {
			n = uint32(len(resp) - 4)
		}
		total += copy(p[total:], resp[4:4+int(n)])
	}
	return total, nil
}

// WriteAt writes all of p starting at offset off.
func (f *File) WriteAt(p []byte, off int64) (int, error) {
	chunk := int(f.c.msize) - 23 // header+fid+offset+count
	if chunk <= 0 || chunk > 1<<20 {
		chunk = 8192
	}
	total := 0
	for total < len(p) {
		n := len(p) - total
		if n > chunk {
			n = chunk
		}
		var b bytes.Buffer
		_ = binary.Write(&b, binary.LittleEndian, f.fid)
		_ = binary.Write(&b, binary.LittleEndian, uint64(off)+uint64(total))
		_ = binary.Write(&b, binary.LittleEndian, uint32(n))
		b.Write(p[total : total+n])
		resp, err := f.c.rpc(tWrite, b.Bytes())
		if err != nil {
			return total, err
		}
		if len(resp) < 4 {
			return total, fmt.Errorf("short_rwrite")
		}
		wrote := int(binary.LittleEndian.Uint32(resp[:4]))
		if wrote <= 0 {
			return total, fmt.Errorf("write_made_no_progress")
		}
		if wrote > n {
			wrote = n
		}
		total += wrote
	}
	return total, nil
}

// Close clunks the underlying fid.
func (f *File) Close() error { return f.c.clunk(f.fid) }

// --- wire layer ------------------------------------------------------------

// rpc sends a T-message and returns the matching R-message payload, decoding
// Rerror into a Go error.
func (c *Client) rpc(typ uint8, payload []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tag++
	tag := c.tag
	if err := writeMessage(c.conn, typ, tag, payload); err != nil {
		return nil, err
	}
	rtype, rtag, rpayload, err := readMessage(c.conn)
	if err != nil {
		return nil, err
	}
	if rtag != tag {
		return nil, fmt.Errorf("tag_mismatch want=%d got=%d", tag, rtag)
	}
	if rtype == rError {
		msg, _, _ := unpackString(rpayload, 0)
		return nil, fmt.Errorf("9p error: %s", msg)
	}
	if rtype != expectedReply(typ) {
		return nil, fmt.Errorf("unexpected reply type %d for request %d", rtype, typ)
	}
	return rpayload, nil
}

func expectedReply(t uint8) uint8 {
	switch t {
	case tVersion:
		return rVersion
	case tAttach:
		return rAttach
	case tWalk:
		return rWalk
	case tOpen:
		return rOpen
	case tCreate:
		return rCreate
	case tRead:
		return rRead
	case tWrite:
		return rWrite
	case tClunk:
		return rClunk
	case tRemove:
		return rRemove
	case tStat:
		return rStat
	default:
		return 0
	}
}

func writeMessage(w io.Writer, typ uint8, tag uint16, payload []byte) error {
	size := uint32(7 + len(payload))
	header := make([]byte, 7)
	binary.LittleEndian.PutUint32(header[:4], size)
	header[4] = typ
	binary.LittleEndian.PutUint16(header[5:7], tag)
	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readMessage(r io.Reader) (uint8, uint16, []byte, error) {
	header := make([]byte, 7)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, 0, nil, err
	}
	size := binary.LittleEndian.Uint32(header[:4])
	if size < 7 || size > 1<<24 {
		return 0, 0, nil, fmt.Errorf("invalid_9p_message_size_%d", size)
	}
	payload := make([]byte, int(size)-7)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, 0, nil, err
	}
	return header[4], binary.LittleEndian.Uint16(header[5:7]), payload, nil
}

// parseStat decodes one stat record (a leading size[2] followed by the body)
// starting at off, returning the entry and the offset just past it.
func parseStat(buf []byte, off int) (DirEntry, int, error) {
	if off+2 > len(buf) {
		return DirEntry{}, off, fmt.Errorf("short_stat_size")
	}
	bodyLen := int(binary.LittleEndian.Uint16(buf[off : off+2]))
	off += 2
	if off+bodyLen > len(buf) {
		return DirEntry{}, off, fmt.Errorf("short_stat_body")
	}
	body := buf[off : off+bodyLen]
	end := off + bodyLen
	// body: type[2] dev[4] qid(type[1] ver[4] path[8]) mode[4] atime[4] mtime[4] length[8] name[s] ...
	p := 2 + 4 // skip type, dev
	if p+13 > len(body) {
		return DirEntry{}, end, fmt.Errorf("short_stat_qid")
	}
	p += 13 // qid
	if p+4 > len(body) {
		return DirEntry{}, end, fmt.Errorf("short_stat_mode")
	}
	mode := binary.LittleEndian.Uint32(body[p : p+4])
	p += 4
	p += 4 + 4 // atime, mtime
	if p+8 > len(body) {
		return DirEntry{}, end, fmt.Errorf("short_stat_length")
	}
	length := binary.LittleEndian.Uint64(body[p : p+8])
	p += 8
	name, _, err := unpackString(body, p)
	if err != nil {
		return DirEntry{}, end, err
	}
	return DirEntry{Name: name, IsDir: mode&permDir != 0, Size: length}, end, nil
}

func packString(w io.Writer, value string) {
	raw := []byte(value)
	_ = binary.Write(w, binary.LittleEndian, uint16(len(raw)))
	_, _ = w.Write(raw)
}

func unpackString(buf []byte, offset int) (string, int, error) {
	if offset+2 > len(buf) {
		return "", offset, fmt.Errorf("short_string_len")
	}
	ln := int(binary.LittleEndian.Uint16(buf[offset : offset+2]))
	offset += 2
	if offset+ln > len(buf) {
		return "", offset, fmt.Errorf("short_string_body")
	}
	return string(buf[offset : offset+ln]), offset + ln, nil
}

// splitPath breaks a slash-separated relative path into walk components,
// dropping empties and ".".
func splitPath(path string) []string {
	path = strings.Trim(path, "/")
	if path == "" {
		return nil
	}
	parts := strings.Split(path, "/")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" || p == "." {
			continue
		}
		out = append(out, p)
	}
	return out
}

// splitParent returns the parent path and final element of path.
func splitParent(path string) (string, string) {
	names := splitPath(path)
	if len(names) == 0 {
		return "", ""
	}
	return strings.Join(names[:len(names)-1], "/"), names[len(names)-1]
}
