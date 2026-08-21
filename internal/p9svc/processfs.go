package p9svc

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"weaverssh/containerstream"
)

const maxProcessFSRequests = 128

// ProcessFSServer exposes one synthetic process directory per typed ServiceFS
// stream. It never joins that directory to the host OS export.
type ProcessFSServer struct {
	Filesystem       *containerstream.ProcessFS
	ResolvePrincipal func(containerstream.ProcessFSOpenMetadata) (string, error)
}

// ServeBound verifies broker provenance, allocates a process session, and
// serves its ctl/stdin/stdout/stderr/status files directly on transport.
func (s *ProcessFSServer) ServeBound(ctx context.Context, transport io.ReadWriteCloser, rawMetadata []byte) error {
	if s == nil || s.Filesystem == nil || transport == nil {
		return errors.New("p9svc: incomplete ProcessFS server")
	}
	defer transport.Close()
	if ctx == nil {
		ctx = context.Background()
	}
	metadata, err := containerstream.ParseProcessFSOpenMetadata(rawMetadata)
	if err != nil {
		return err
	}
	if metadata.SourceNode == "" || metadata.SourceBinding == "" || metadata.ChainSHA256 == "" {
		return errors.New("p9svc: ProcessFS metadata was not bound by the broker")
	}
	target, err := containerstream.ParseURI(metadata.TargetURI)
	if err != nil || target.Endpoint != metadata.TargetNode || target.FilePath != containerstream.ProcessRoot {
		return errors.New("p9svc: ProcessFS target does not match routed node")
	}
	principal := metadata.SourceNode
	if s.ResolvePrincipal != nil {
		principal, err = s.ResolvePrincipal(metadata)
		if err != nil {
			return err
		}
	}
	principal = strings.TrimSpace(principal)
	if principal == "" {
		return errors.New("p9svc: empty ProcessFS principal")
	}
	session, err := s.Filesystem.CreateSessionFor(containerstream.ProcessIdentity{
		Principal: principal, SourceNode: metadata.SourceNode,
		SourceBinding: metadata.SourceBinding, ChainSHA256: metadata.ChainSHA256,
	}, target)
	if err != nil {
		return err
	}
	rootURI, uriErr := session.URI("")
	if uriErr != nil {
		_ = session.Close()
		return uriErr
	}

	serveContext, cancel := context.WithCancel(ctx)
	defer cancel()
	protocol := newProcess9PSession(serveContext, transport, s.Filesystem, session)
	go func() {
		<-serveContext.Done()
		_ = transport.Close()
	}()
	serveErr := protocol.serve()
	cancel()
	removeErr := s.Filesystem.RemoveSession(rootURI)
	// Remove the process before locking and closing fids. A streaming Tread may
	// currently hold its fid lock while blocked in the provider; process close
	// releases that read and prevents teardown from deadlocking.
	protocol.closeFids(false)
	protocol.wait()
	_ = transport.Close()
	if normalProcessFSEnd(serveErr) {
		serveErr = nil
	}
	if errors.Is(removeErr, containerstream.ErrProcessNotFound) {
		removeErr = nil
	}
	return errors.Join(serveErr, removeErr)
}

type process9PSession struct {
	ctx       context.Context
	transport io.ReadWriteCloser
	fs        *containerstream.ProcessFS
	process   *containerstream.ProcessSession
	created   time.Time

	mu      sync.Mutex
	msize   uint32
	version string
	fids    map[uint32]*processFID
	closed  bool

	writeMu sync.Mutex
	workers sync.WaitGroup
	limit   chan struct{}
}

type processFID struct {
	mu      sync.Mutex
	path    string
	opened  bool
	mode    uint8
	offset  uint64
	reader  io.ReadCloser
	writer  io.WriteCloser
	data    []byte
	reading bool
	writing bool
}

func newProcess9PSession(ctx context.Context, transport io.ReadWriteCloser, fs *containerstream.ProcessFS, process *containerstream.ProcessSession) *process9PSession {
	return &process9PSession{
		ctx: ctx, transport: transport, fs: fs, process: process, created: process.Status().CreatedAt,
		msize: 8192, version: servedVersion, fids: make(map[uint32]*processFID),
		limit: make(chan struct{}, maxProcessFSRequests),
	}
}

func (s *process9PSession) serve() error {
	for {
		msg, err := readMessage(s.transport)
		if err != nil {
			return err
		}
		s.limit <- struct{}{}
		s.workers.Add(1)
		go func(msg message) {
			defer func() {
				<-s.limit
				s.workers.Done()
			}()
			if handleErr := s.handle(msg); handleErr != nil {
				s.writeMu.Lock()
				_ = writeError(s.transport, msg.Tag, s.currentVersion(), handleErr.Error())
				s.writeMu.Unlock()
			}
		}(msg)
	}
}

func (s *process9PSession) wait() { s.workers.Wait() }

func (s *process9PSession) currentVersion() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.version
}

func (s *process9PSession) reply(typ uint8, tag uint16, payload []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return writeMessage(s.transport, typ, tag, payload)
}

func (s *process9PSession) handle(msg message) error {
	switch msg.Type {
	case Tversion:
		return s.handleVersion(msg)
	case Tattach:
		return s.handleAttach(msg)
	case Twalk:
		return s.handleWalk(msg)
	case Topen:
		return s.handleOpen(msg)
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
	case Tcreate:
		return errors.New("synthetic_files_are_fixed")
	default:
		return fmt.Errorf("unsupported_msg_%d", msg.Type)
	}
}

func (s *process9PSession) handleVersion(msg message) error {
	if len(msg.Payload) < 6 {
		return errors.New("short_tversion")
	}
	requested, _, err := unpackString(msg.Payload, 4)
	if err != nil {
		return fmt.Errorf("bad_tversion: %w", err)
	}
	msize := binary.LittleEndian.Uint32(msg.Payload[:4])
	if msize == 0 || msize > 1<<20 {
		msize = 8192
	}
	selected := selectVersion(requested)
	s.mu.Lock()
	s.msize = minUint32(msize, 65536)
	if selected != "unknown" {
		s.version = selected
	}
	negotiated := s.msize
	s.mu.Unlock()
	var payload bytes.Buffer
	_ = binary.Write(&payload, binary.LittleEndian, negotiated)
	packString(&payload, selected)
	return s.reply(Rversion, msg.Tag, payload.Bytes())
}

func (s *process9PSession) handleAttach(msg message) error {
	if len(msg.Payload) < 8 {
		return errors.New("short_tattach")
	}
	fid := binary.LittleEndian.Uint32(msg.Payload[:4])
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errors.New("session_closed")
	}
	if _, exists := s.fids[fid]; exists {
		s.mu.Unlock()
		return errors.New("fid_in_use")
	}
	s.fids[fid] = &processFID{path: ""}
	s.mu.Unlock()
	return s.reply(Rattach, msg.Tag, s.qid("").bytes())
}

func (s *process9PSession) handleWalk(msg message) error {
	if len(msg.Payload) < 10 {
		return errors.New("short_twalk")
	}
	fid := binary.LittleEndian.Uint32(msg.Payload[:4])
	newfid := binary.LittleEndian.Uint32(msg.Payload[4:8])
	namesCount := int(binary.LittleEndian.Uint16(msg.Payload[8:10]))
	offset := 10
	names := make([]string, 0, namesCount)
	for index := 0; index < namesCount; index++ {
		name, next, err := unpackString(msg.Payload, offset)
		if err != nil {
			return fmt.Errorf("bad_twalk: %w", err)
		}
		offset = next
		names = append(names, name)
	}
	s.mu.Lock()
	base, ok := s.fids[fid]
	if !ok {
		s.mu.Unlock()
		return errors.New("unknown_fid")
	}
	if _, exists := s.fids[newfid]; exists && newfid != fid {
		s.mu.Unlock()
		return errors.New("fid_in_use")
	}
	base.mu.Lock()
	basePath, baseOpened := base.path, base.opened
	base.mu.Unlock()
	if baseOpened {
		s.mu.Unlock()
		return errors.New("walk_from_open_fid")
	}
	path := basePath
	qids := make([]qid, 0, namesCount)
	for _, name := range names {
		if name == "." {
			continue
		}
		if path != "" || !validProcessFile(name) {
			s.mu.Unlock()
			return errors.New("walk_not_found")
		}
		path = name
		qids = append(qids, s.qid(path))
	}
	s.fids[newfid] = &processFID{path: path}
	s.mu.Unlock()
	return s.writeWalk(msg.Tag, qids)
}

func (s *process9PSession) writeWalk(tag uint16, qids []qid) error {
	var payload bytes.Buffer
	_ = binary.Write(&payload, binary.LittleEndian, uint16(len(qids)))
	for _, value := range qids {
		payload.Write(value.bytes())
	}
	return s.reply(Rwalk, tag, payload.Bytes())
}

func (s *process9PSession) handleOpen(msg message) error {
	if len(msg.Payload) < 5 {
		return errors.New("short_topen")
	}
	fid := binary.LittleEndian.Uint32(msg.Payload[:4])
	mode := msg.Payload[4]
	state, err := s.fid(fid)
	if err != nil {
		return err
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.opened {
		return errors.New("fid_already_open")
	}
	access := mode & openWriteMask
	if state.path == "" {
		if access != 0 || mode&openTrunc != 0 {
			return errors.New("process_root_is_read_only")
		}
		state.data = s.directoryBytes()
	} else if processFileWritable(state.path) {
		if access != 1 {
			return errors.New("synthetic_file_is_write_only")
		}
		uri, uriErr := s.process.URI(state.path)
		if uriErr != nil {
			return uriErr
		}
		state.writer, err = s.fs.OpenWriter(s.ctx, uri)
		if err != nil {
			return err
		}
	} else {
		if access != 0 || mode&openTrunc != 0 {
			return errors.New("synthetic_file_is_read_only")
		}
		uri, uriErr := s.process.URI(state.path)
		if uriErr != nil {
			return uriErr
		}
		state.reader, err = s.fs.OpenReader(s.ctx, uri)
		if err != nil {
			return err
		}
	}
	state.mode = mode
	state.opened = true
	var payload bytes.Buffer
	payload.Write(s.qid(state.path).bytes())
	_ = binary.Write(&payload, binary.LittleEndian, uint32(0))
	return s.reply(Ropen, msg.Tag, payload.Bytes())
}

func (s *process9PSession) handleRead(msg message) error {
	if len(msg.Payload) < 16 {
		return errors.New("short_tread")
	}
	fid := binary.LittleEndian.Uint32(msg.Payload[:4])
	offset := binary.LittleEndian.Uint64(msg.Payload[4:12])
	count := binary.LittleEndian.Uint32(msg.Payload[12:16])
	if count > 1<<20 {
		count = 1 << 20
	}
	state, err := s.fid(fid)
	if err != nil {
		return err
	}
	state.mu.Lock()
	if !state.opened || state.mode&openWriteMask != 0 {
		state.mu.Unlock()
		return errors.New("fid_not_open_for_read")
	}
	var data []byte
	if state.data != nil {
		if offset < uint64(len(state.data)) {
			data = state.data[offset:]
			if uint32(len(data)) > count {
				data = data[:count]
			}
		}
		state.mu.Unlock()
	} else {
		if state.reader == nil || state.reading || offset != state.offset {
			state.mu.Unlock()
			return errors.New("stream_read_requires_sequential_offset")
		}
		reader := state.reader
		state.reading = true
		state.mu.Unlock()
		buffer := make([]byte, count)
		read, readErr := reader.Read(buffer)
		state.mu.Lock()
		state.reading = false
		state.offset += uint64(read)
		state.mu.Unlock()
		if readErr != nil && !errors.Is(readErr, io.EOF) && read == 0 {
			return readErr
		}
		data = buffer[:read]
	}
	var payload bytes.Buffer
	_ = binary.Write(&payload, binary.LittleEndian, uint32(len(data)))
	payload.Write(data)
	return s.reply(Rread, msg.Tag, payload.Bytes())
}

func (s *process9PSession) handleWrite(msg message) error {
	if len(msg.Payload) < 16 {
		return errors.New("short_twrite")
	}
	fid := binary.LittleEndian.Uint32(msg.Payload[:4])
	offset := binary.LittleEndian.Uint64(msg.Payload[4:12])
	count := binary.LittleEndian.Uint32(msg.Payload[12:16])
	if int(count) > len(msg.Payload)-16 {
		count = uint32(len(msg.Payload) - 16)
	}
	state, err := s.fid(fid)
	if err != nil {
		return err
	}
	state.mu.Lock()
	if !state.opened || state.writer == nil || state.writing || state.mode&openWriteMask != 1 || offset != state.offset {
		state.mu.Unlock()
		return errors.New("fid_not_open_for_sequential_write")
	}
	writer := state.writer
	state.writing = true
	state.mu.Unlock()
	written, err := writer.Write(msg.Payload[16 : 16+int(count)])
	state.mu.Lock()
	state.writing = false
	state.offset += uint64(written)
	state.mu.Unlock()
	if err != nil {
		return err
	}
	var payload bytes.Buffer
	_ = binary.Write(&payload, binary.LittleEndian, uint32(written))
	return s.reply(Rwrite, msg.Tag, payload.Bytes())
}

func (s *process9PSession) handleClunk(msg message) error {
	if len(msg.Payload) < 4 {
		return errors.New("short_tclunk")
	}
	fid := binary.LittleEndian.Uint32(msg.Payload[:4])
	state, err := s.takeFid(fid)
	if err != nil {
		return err
	}
	if err := closeProcessFID(state, true); err != nil {
		return err
	}
	return s.reply(Rclunk, msg.Tag, nil)
}

func (s *process9PSession) handleRemove(msg message) error {
	if len(msg.Payload) < 4 {
		return errors.New("short_tremove")
	}
	fid := binary.LittleEndian.Uint32(msg.Payload[:4])
	state, err := s.takeFid(fid)
	if err != nil {
		return err
	}
	_ = closeProcessFID(state, false)
	return errors.New("synthetic_files_cannot_be_removed")
}

func (s *process9PSession) handleStat(msg message) error {
	if len(msg.Payload) < 4 {
		return errors.New("short_tstat")
	}
	state, err := s.fid(binary.LittleEndian.Uint32(msg.Payload[:4]))
	if err != nil {
		return err
	}
	state.mu.Lock()
	path := state.path
	var size uint64
	if state.data != nil {
		size = uint64(len(state.data))
	} else if path == containerstream.ProcessFileStatus {
		size = uint64(len(s.statusBytes()))
	} else if path == "" {
		size = uint64(len(s.directoryBytes()))
	}
	state.mu.Unlock()
	stat := s.stat(path, size)
	var payload bytes.Buffer
	_ = binary.Write(&payload, binary.LittleEndian, uint16(len(stat)))
	payload.Write(stat)
	return s.reply(Rstat, msg.Tag, payload.Bytes())
}

func (s *process9PSession) fid(fid uint32) (*processFID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.fids[fid]
	if !ok {
		return nil, errors.New("unknown_fid")
	}
	return state, nil
}

func (s *process9PSession) takeFid(fid uint32) (*processFID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.fids[fid]
	if !ok {
		return nil, errors.New("unknown_fid")
	}
	delete(s.fids, fid)
	return state, nil
}

func (s *process9PSession) closeFids(explicit bool) {
	s.mu.Lock()
	s.closed = true
	fids := make([]*processFID, 0, len(s.fids))
	for _, state := range s.fids {
		fids = append(fids, state)
	}
	s.fids = make(map[uint32]*processFID)
	s.mu.Unlock()
	for _, state := range fids {
		_ = closeProcessFID(state, explicit)
	}
}

func closeProcessFID(state *processFID, explicit bool) error {
	if state == nil {
		return nil
	}
	state.mu.Lock()
	reader, writer, path := state.reader, state.writer, state.path
	state.reader = nil
	state.writer = nil
	state.mu.Unlock()
	var err error
	if reader != nil {
		err = reader.Close()
	}
	if writer != nil {
		// A partially delivered ctl record is discarded on transport failure;
		// only an explicit Tclunk commits the transactional control message.
		if explicit || path != containerstream.ProcessFileControl {
			err = errors.Join(err, writer.Close())
		}
	}
	return err
}

func (s *process9PSession) qid(path string) qid {
	kind := qidFile
	if path == "" {
		kind = qidDir
	}
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(s.process.ID()))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(path))
	return qid{Type: kind, Version: uint32(s.created.Unix()), Path: hash.Sum64()}
}

func (s *process9PSession) stat(path string, size uint64) []byte {
	name, mode := path, uint32(0o400)
	if path == "" {
		name, mode = s.process.ID(), permDir|0o500
	} else if processFileWritable(path) {
		mode = 0o200
	}
	var body bytes.Buffer
	_ = binary.Write(&body, binary.LittleEndian, uint16(0))
	_ = binary.Write(&body, binary.LittleEndian, uint32(0))
	body.Write(s.qid(path).bytes())
	_ = binary.Write(&body, binary.LittleEndian, mode)
	modified := uint32(s.created.Unix())
	_ = binary.Write(&body, binary.LittleEndian, modified)
	_ = binary.Write(&body, binary.LittleEndian, modified)
	_ = binary.Write(&body, binary.LittleEndian, size)
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

func (s *process9PSession) directoryBytes() []byte {
	files := []string{
		containerstream.ProcessFileControl,
		containerstream.ProcessFileStdin,
		containerstream.ProcessFileStdout,
		containerstream.ProcessFileStderr,
		containerstream.ProcessFileStatus,
	}
	sort.Strings(files)
	var out bytes.Buffer
	for _, file := range files {
		var size uint64
		if file == containerstream.ProcessFileStatus {
			size = uint64(len(s.statusBytes()))
		}
		out.Write(s.stat(file, size))
	}
	return out.Bytes()
}

func (s *process9PSession) statusBytes() []byte {
	payload, err := json.Marshal(s.process.Status())
	if err != nil {
		return []byte("{}\n")
	}
	return append(payload, '\n')
}

func validProcessFile(name string) bool {
	switch name {
	case containerstream.ProcessFileControl, containerstream.ProcessFileStdin,
		containerstream.ProcessFileStdout, containerstream.ProcessFileStderr,
		containerstream.ProcessFileStatus:
		return true
	default:
		return false
	}
}

func processFileWritable(name string) bool {
	return name == containerstream.ProcessFileControl || name == containerstream.ProcessFileStdin
}

func normalProcessFSEnd(err error) bool {
	return err == nil || errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled)
}
