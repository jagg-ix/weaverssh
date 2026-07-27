package p9svc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	Tversion uint8 = 100
	Rversion uint8 = 101
	Rerror   uint8 = 107
	Tattach  uint8 = 104
	Rattach  uint8 = 105
	Twalk    uint8 = 110
	Rwalk    uint8 = 111
	Topen    uint8 = 112
	Ropen    uint8 = 113
	Tcreate  uint8 = 114
	Rcreate  uint8 = 115
	Tread    uint8 = 116
	Rread    uint8 = 117
	Twrite   uint8 = 118
	Rwrite   uint8 = 119
	Tclunk   uint8 = 120
	Rclunk   uint8 = 121
	Tremove  uint8 = 122
	Rremove  uint8 = 123
	Tstat    uint8 = 124
	Rstat    uint8 = 125
)

const (
	qidFile uint8 = 0x00
	qidDir  uint8 = 0x80
)

// 9P open-mode and perm bits exercised by the write path.
const (
	openWriteMask uint8  = 0x03       // low bits: OREAD/OWRITE/ORDWR/OEXEC
	openTrunc     uint8  = 0x10       // OTRUNC
	permDir       uint32 = 0x80000000 // DMDIR
)

// servedVersion is the single 9P dialect this server implements. Clients that
// propose a richer dialect (9P2000.L / 9P2000.u, as the Linux kernel v9fs
// client and QEMU virtio-9p do) negotiate down to it per the 9P spec, which is
// what makes the export mountable by the kernel, FUSE, and libvirt guests.
const servedVersion = "9P2000"

type Config struct {
	Root              string
	Addr              string
	ReadOnly          bool
	AllowUnknownUsers bool
	Logger            *log.Logger
}

type Server struct {
	root     string
	addr     string
	readOnly bool
	logger   *log.Logger
}

type fidState struct {
	rel    string
	path   string
	opened bool
	isDir  bool
}

type session struct {
	server  *Server
	conn    net.Conn
	msize   uint32
	version string
	fids    map[uint32]fidState
}

type qid struct {
	Type    uint8
	Version uint32
	Path    uint64
}

type message struct {
	Type    uint8
	Tag     uint16
	Payload []byte
}

func New(config Config) (*Server, error) {
	root := strings.TrimSpace(config.Root)
	if root == "" {
		root = "."
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve root: %w", err)
	}
	rootEval, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("validate root: %w", err)
	}
	info, err := os.Stat(rootEval)
	if err != nil {
		return nil, fmt.Errorf("stat root: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("root is not a directory: %s", rootEval)
	}
	addr := strings.TrimSpace(config.Addr)
	if addr == "" {
		addr = "127.0.0.1:5640"
	}
	logger := config.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	return &Server{root: rootEval, addr: addr, readOnly: config.ReadOnly, logger: logger}, nil
}

func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	return s.Serve(ln)
}

func (s *Server) Serve(ln net.Listener) error {
	defer ln.Close()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer conn.Close()
			if err := s.handleConn(conn); err != nil {
				s.logger.Printf("9p session ended: %v", err)
			}
		}()
	}
}

func (s *Server) handleConn(conn net.Conn) error {
	sess := &session{server: s, conn: conn, msize: 8192, version: "9P2000", fids: map[uint32]fidState{}}
	for {
		msg, err := readMessage(conn)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if err := sess.handle(msg); err != nil {
			_ = writeError(conn, msg.Tag, sess.version, err.Error())
		}
	}
}

func (s *session) handle(msg message) error {
	switch msg.Type {
	case Tversion:
		return s.handleVersion(msg)
	case Tattach:
		return s.handleAttach(msg)
	case Twalk:
		return s.handleWalk(msg)
	case Topen:
		return s.handleOpen(msg)
	case Tcreate:
		return s.handleCreate(msg)
	case Tread:
		return s.handleRead(msg)
	case Twrite:
		return s.handleWrite(msg)
	case Tclunk:
		return s.handleClunk(msg)
	case Tremove:
		return s.handleRemove(msg)
	case Tstat:
		return s.handleStat(msg)
	default:
		return fmt.Errorf("unsupported_msg_%d", msg.Type)
	}
}

func (s *session) handleVersion(msg message) error {
	if len(msg.Payload) < 6 {
		return fmt.Errorf("short_tversion")
	}
	msize := binary.LittleEndian.Uint32(msg.Payload[:4])
	version, _, err := unpackString(msg.Payload, 4)
	if err != nil {
		return fmt.Errorf("bad_tversion: %w", err)
	}
	selected := selectVersion(version)
	if selected != "unknown" {
		s.version = selected
	}
	if msize == 0 || msize > 1<<20 {
		msize = 8192
	}
	s.msize = minUint32(msize, 65536)
	var payload bytes.Buffer
	_ = binary.Write(&payload, binary.LittleEndian, s.msize)
	packString(&payload, selected)
	return writeMessage(s.conn, Rversion, msg.Tag, payload.Bytes())
}

func (s *session) handleAttach(msg message) error {
	if len(msg.Payload) < 8 {
		return fmt.Errorf("short_tattach")
	}
	fid := binary.LittleEndian.Uint32(msg.Payload[:4])
	root, err := s.server.resolve("")
	if err != nil {
		return err
	}
	info, err := os.Stat(root)
	if err != nil {
		return err
	}
	s.fids[fid] = fidState{rel: "", path: root, isDir: true}
	return writeMessage(s.conn, Rattach, msg.Tag, qidFor("", info).bytes())
}

func (s *session) handleWalk(msg message) error {
	if len(msg.Payload) < 10 {
		return fmt.Errorf("short_twalk")
	}
	fid := binary.LittleEndian.Uint32(msg.Payload[:4])
	newfid := binary.LittleEndian.Uint32(msg.Payload[4:8])
	nwname := int(binary.LittleEndian.Uint16(msg.Payload[8:10]))
	off := 10
	names := make([]string, 0, nwname)
	for i := 0; i < nwname; i++ {
		name, next, err := unpackString(msg.Payload, off)
		if err != nil {
			return fmt.Errorf("bad_twalk: %w", err)
		}
		off = next
		names = append(names, name)
	}
	base, ok := s.fids[fid]
	if !ok {
		return fmt.Errorf("unknown_fid")
	}
	rel := base.rel
	qids := make([]qid, 0, len(names))
	if nwname == 0 {
		s.fids[newfid] = base
		return writeWalkReply(s.conn, msg.Tag, qids)
	}
	for _, name := range names {
		if name == "" || strings.ContainsAny(name, `/\\`) || name == ".." {
			return fmt.Errorf("invalid_walk_name")
		}
		if name == "." {
			continue
		}
		rel = filepath.ToSlash(filepath.Join(filepath.FromSlash(rel), name))
		path, err := s.server.resolve(rel)
		if err != nil {
			return err
		}
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("walk_not_found")
		}
		qids = append(qids, qidFor(rel, info))
	}
	path, err := s.server.resolve(rel)
	if err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	s.fids[newfid] = fidState{rel: rel, path: path, isDir: info.IsDir()}
	return writeWalkReply(s.conn, msg.Tag, qids)
}

func (s *session) handleOpen(msg message) error {
	if len(msg.Payload) < 5 {
		return fmt.Errorf("short_topen")
	}
	fid := binary.LittleEndian.Uint32(msg.Payload[:4])
	mode := msg.Payload[4]
	st, ok := s.fids[fid]
	if !ok {
		return fmt.Errorf("unknown_fid")
	}
	wantsWrite := mode&openWriteMask != 0 || mode&openTrunc != 0
	if s.server.readOnly && wantsWrite {
		return fmt.Errorf("read_only")
	}
	info, err := os.Stat(st.path)
	if err != nil {
		return err
	}
	if mode&openTrunc != 0 && !info.IsDir() {
		if err := os.Truncate(st.path, 0); err != nil {
			return fmt.Errorf("truncate: %w", err)
		}
		if info, err = os.Stat(st.path); err != nil {
			return err
		}
	}
	st.opened = true
	st.isDir = info.IsDir()
	s.fids[fid] = st
	var payload bytes.Buffer
	payload.Write(qidFor(st.rel, info).bytes())
	_ = binary.Write(&payload, binary.LittleEndian, uint32(0))
	return writeMessage(s.conn, Ropen, msg.Tag, payload.Bytes())
}

func (s *session) handleRead(msg message) error {
	if len(msg.Payload) < 16 {
		return fmt.Errorf("short_tread")
	}
	fid := binary.LittleEndian.Uint32(msg.Payload[:4])
	offset := binary.LittleEndian.Uint64(msg.Payload[4:12])
	count := binary.LittleEndian.Uint32(msg.Payload[12:16])
	st, ok := s.fids[fid]
	if !ok {
		return fmt.Errorf("unknown_fid")
	}
	info, err := os.Stat(st.path)
	if err != nil {
		return err
	}
	if count > 1<<20 {
		count = 1 << 20 // bound a single reply
	}
	var data []byte
	if info.IsDir() {
		// Directory listings are generated whole, then sliced by offset.
		all, derr := s.readDir(st.rel, st.path)
		if derr != nil {
			return derr
		}
		if offset < uint64(len(all)) {
			data = all[offset:]
			if uint32(len(data)) > count {
				data = data[:count]
			}
		}
	} else {
		// Files are read positionally so a single Tread never loads the
		// whole file — the FUSE mount streams ranges over large files.
		f, oerr := os.Open(st.path)
		if oerr != nil {
			return oerr
		}
		buf := make([]byte, count)
		n, rerr := f.ReadAt(buf, int64(offset))
		_ = f.Close()
		if rerr != nil && rerr != io.EOF && n == 0 {
			return rerr
		}
		data = buf[:n]
	}
	var payload bytes.Buffer
	_ = binary.Write(&payload, binary.LittleEndian, uint32(len(data)))
	payload.Write(data)
	return writeMessage(s.conn, Rread, msg.Tag, payload.Bytes())
}

// handleCreate creates a file or directory named in msg under the directory fid,
// then rebinds the fid to the new entry (9P2000 semantics). Write-gated.
func (s *session) handleCreate(msg message) error {
	if s.server.readOnly {
		return fmt.Errorf("read_only")
	}
	if len(msg.Payload) < 4 {
		return fmt.Errorf("short_tcreate")
	}
	fid := binary.LittleEndian.Uint32(msg.Payload[:4])
	name, off, err := unpackString(msg.Payload, 4)
	if err != nil {
		return fmt.Errorf("bad_tcreate: %w", err)
	}
	if off+5 > len(msg.Payload) {
		return fmt.Errorf("short_tcreate")
	}
	perm := binary.LittleEndian.Uint32(msg.Payload[off : off+4])
	// msg.Payload[off+4] is the open mode; we create then leave the fid usable.
	st, ok := s.fids[fid]
	if !ok {
		return fmt.Errorf("unknown_fid")
	}
	if !st.isDir {
		return fmt.Errorf("create_in_non_dir")
	}
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("invalid_create_name")
	}
	childRel := filepath.ToSlash(filepath.Join(filepath.FromSlash(st.rel), name))
	childPath, err := s.server.resolve(childRel)
	if err != nil {
		return err
	}
	isDir := perm&permDir != 0
	if isDir {
		if err := os.Mkdir(childPath, 0o755); err != nil {
			return fmt.Errorf("mkdir: %w", err)
		}
	} else {
		f, err := os.OpenFile(childPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(perm&0o777))
		if err != nil {
			return fmt.Errorf("create: %w", err)
		}
		_ = f.Close()
	}
	info, err := os.Stat(childPath)
	if err != nil {
		return err
	}
	s.fids[fid] = fidState{rel: childRel, path: childPath, opened: true, isDir: isDir}
	var payload bytes.Buffer
	payload.Write(qidFor(childRel, info).bytes())
	_ = binary.Write(&payload, binary.LittleEndian, uint32(0)) // iounit
	return writeMessage(s.conn, Rcreate, msg.Tag, payload.Bytes())
}

// handleWrite writes data at the given offset to the file behind fid. Write-gated.
func (s *session) handleWrite(msg message) error {
	if s.server.readOnly {
		return fmt.Errorf("read_only")
	}
	if len(msg.Payload) < 16 {
		return fmt.Errorf("short_twrite")
	}
	fid := binary.LittleEndian.Uint32(msg.Payload[:4])
	offset := binary.LittleEndian.Uint64(msg.Payload[4:12])
	count := binary.LittleEndian.Uint32(msg.Payload[12:16])
	st, ok := s.fids[fid]
	if !ok {
		return fmt.Errorf("unknown_fid")
	}
	if st.isDir {
		return fmt.Errorf("write_to_dir")
	}
	if int(count) > len(msg.Payload)-16 {
		count = uint32(len(msg.Payload) - 16)
	}
	data := msg.Payload[16 : 16+int(count)]
	f, err := os.OpenFile(st.path, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open_for_write: %w", err)
	}
	n, werr := f.WriteAt(data, int64(offset))
	cerr := f.Close()
	if werr != nil {
		return fmt.Errorf("write: %w", werr)
	}
	if cerr != nil {
		return cerr
	}
	var payload bytes.Buffer
	_ = binary.Write(&payload, binary.LittleEndian, uint32(n))
	return writeMessage(s.conn, Rwrite, msg.Tag, payload.Bytes())
}

// handleRemove deletes the file or empty directory behind fid and clunks it. Write-gated.
func (s *session) handleRemove(msg message) error {
	if len(msg.Payload) < 4 {
		return fmt.Errorf("short_tremove")
	}
	fid := binary.LittleEndian.Uint32(msg.Payload[:4])
	st, ok := s.fids[fid]
	delete(s.fids, fid) // 9P clunks the fid even on error
	if !ok {
		return fmt.Errorf("unknown_fid")
	}
	if s.server.readOnly {
		return fmt.Errorf("read_only")
	}
	if st.rel == "" {
		return fmt.Errorf("refuse_remove_root")
	}
	if err := os.Remove(st.path); err != nil {
		return fmt.Errorf("remove: %w", err)
	}
	return writeMessage(s.conn, Rremove, msg.Tag, nil)
}

func (s *session) handleClunk(msg message) error {
	if len(msg.Payload) < 4 {
		return fmt.Errorf("short_tclunk")
	}
	fid := binary.LittleEndian.Uint32(msg.Payload[:4])
	delete(s.fids, fid)
	return writeMessage(s.conn, Rclunk, msg.Tag, nil)
}

func (s *session) handleStat(msg message) error {
	if len(msg.Payload) < 4 {
		return fmt.Errorf("short_tstat")
	}
	fid := binary.LittleEndian.Uint32(msg.Payload[:4])
	st, ok := s.fids[fid]
	if !ok {
		return fmt.Errorf("unknown_fid")
	}
	info, err := os.Stat(st.path)
	if err != nil {
		return err
	}
	stat := statBytes(st.rel, info)
	var payload bytes.Buffer
	_ = binary.Write(&payload, binary.LittleEndian, uint16(len(stat)))
	payload.Write(stat)
	return writeMessage(s.conn, Rstat, msg.Tag, payload.Bytes())
}

func (s *Server) resolve(rel string) (string, error) {
	clean := filepath.Clean(filepath.FromSlash(strings.TrimPrefix(rel, "/")))
	if clean == "." {
		clean = ""
	}
	if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
		return "", fmt.Errorf("path_escape")
	}
	joined := filepath.Join(s.root, clean)
	eval, err := filepath.EvalSymlinks(joined)
	if err != nil {
		if os.IsNotExist(err) {
			return joined, nil
		}
		return "", err
	}
	if !withinRoot(s.root, eval) {
		return "", fmt.Errorf("path_escape")
	}
	return eval, nil
}

func (s *session) readDir(rel string, path string) ([]byte, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	var out bytes.Buffer
	for _, entry := range entries {
		childRel := filepath.ToSlash(filepath.Join(filepath.FromSlash(rel), entry.Name()))
		childPath, err := s.server.resolve(childRel)
		if err != nil {
			continue
		}
		info, err := os.Stat(childPath)
		if err != nil {
			continue
		}
		out.Write(statBytes(childRel, info))
	}
	return out.Bytes(), nil
}

func withinRoot(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	return rel == "." || rel == "" || (!strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel))
}

func selectVersion(requested string) string {
	if requested == servedVersion || strings.HasPrefix(requested, "9P2000.") {
		return servedVersion
	}
	return "unknown"
}

func qidFor(rel string, info os.FileInfo) qid {
	qt := qidFile
	if info.IsDir() {
		qt = qidDir
	}
	return qid{Type: qt, Version: uint32(info.ModTime().Unix()), Path: pathHash(rel, info)}
}

func pathHash(rel string, info os.FileInfo) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(filepath.ToSlash(rel)))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(info.Name()))
	return h.Sum64()
}

func (q qid) bytes() []byte {
	var out bytes.Buffer
	out.WriteByte(q.Type)
	_ = binary.Write(&out, binary.LittleEndian, q.Version)
	_ = binary.Write(&out, binary.LittleEndian, q.Path)
	return out.Bytes()
}

func statBytes(rel string, info os.FileInfo) []byte {
	name := info.Name()
	if rel == "" || rel == "." {
		name = "/"
	}
	var body bytes.Buffer
	_ = binary.Write(&body, binary.LittleEndian, uint16(0)) // type
	_ = binary.Write(&body, binary.LittleEndian, uint32(0)) // dev
	body.Write(qidFor(rel, info).bytes())
	mode := uint32(info.Mode().Perm())
	if info.IsDir() {
		mode |= 0x80000000
	}
	_ = binary.Write(&body, binary.LittleEndian, mode)
	mtime := uint32(info.ModTime().Unix())
	_ = binary.Write(&body, binary.LittleEndian, mtime)
	_ = binary.Write(&body, binary.LittleEndian, mtime)
	_ = binary.Write(&body, binary.LittleEndian, uint64(info.Size()))
	packString(&body, name)
	packString(&body, "weaverssh")
	packString(&body, "weaverssh")
	packString(&body, "")
	payload := body.Bytes()
	var out bytes.Buffer
	_ = binary.Write(&out, binary.LittleEndian, uint16(len(payload)))
	out.Write(payload)
	return out.Bytes()
}

func readMessage(r io.Reader) (message, error) {
	header := make([]byte, 7)
	if _, err := io.ReadFull(r, header); err != nil {
		return message{}, err
	}
	size := binary.LittleEndian.Uint32(header[:4])
	if size < 7 || size > 1<<24 {
		return message{}, fmt.Errorf("invalid_9p_message_size_%d", size)
	}
	payload := make([]byte, int(size)-7)
	if _, err := io.ReadFull(r, payload); err != nil {
		return message{}, err
	}
	return message{Type: header[4], Tag: binary.LittleEndian.Uint16(header[5:7]), Payload: payload}, nil
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

func writeError(w io.Writer, tag uint16, version string, message string) error {
	var payload bytes.Buffer
	packString(&payload, message)
	if version == "9P2000.u" {
		_ = binary.Write(&payload, binary.LittleEndian, uint32(5))
	}
	return writeMessage(w, Rerror, tag, payload.Bytes())
}

func writeWalkReply(w io.Writer, tag uint16, qids []qid) error {
	var payload bytes.Buffer
	_ = binary.Write(&payload, binary.LittleEndian, uint16(len(qids)))
	for _, q := range qids {
		payload.Write(q.bytes())
	}
	return writeMessage(w, Rwalk, tag, payload.Bytes())
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

func minUint32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

func ServeForTest(root string, ln net.Listener) error {
	srv, err := New(Config{Root: root, Addr: ln.Addr().String(), ReadOnly: true})
	if err != nil {
		return err
	}
	return srv.Serve(ln)
}

func WaitForPort(addr string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}
