package p9svc

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"
	"sync"

	"weaverssh/filebackend"
)

type trackedFid struct {
	path      string
	directory bool
}

type trackedRequest struct {
	pending      filebackend.Pending
	requestType  uint8
	fid          uint32
	newfid       uint32
	basePath     string
	targetPath   string
	walkNames    []string
	directory    bool
	mutationPath []string
}

type backendTransport struct {
	ctx     context.Context
	raw     io.ReadWriteCloser
	backend filebackend.API

	readMu   sync.Mutex
	readBuf  []byte
	writeMu  sync.Mutex
	writeBuf []byte
	outMu    sync.Mutex
	stateMu  sync.Mutex

	version string
	fids    map[uint32]trackedFid
	pending map[uint16]trackedRequest
}

func newBackendTransport(ctx context.Context, raw io.ReadWriteCloser, backend filebackend.API) io.ReadWriteCloser {
	if ctx == nil {
		ctx = context.Background()
	}
	return &backendTransport{
		ctx:     ctx,
		raw:     raw,
		backend: backend,
		version: servedVersion,
		fids:    make(map[uint32]trackedFid),
		pending: make(map[uint16]trackedRequest),
	}
}

func (t *backendTransport) Read(destination []byte) (int, error) {
	if len(destination) == 0 {
		return 0, nil
	}
	t.readMu.Lock()
	defer t.readMu.Unlock()
	for len(t.readBuf) == 0 {
		msg, err := readMessage(t.raw)
		if err != nil {
			return 0, err
		}
		if msg.Type == Tversion {
			t.readBuf = encodeMessage(msg)
			break
		}
		event, tracked, ok := t.describeRequest(msg)
		if !ok {
			t.readBuf = encodeMessage(msg)
			break
		}
		pending, err := t.backend.Begin(t.ctx, event)
		if err != nil {
			t.outMu.Lock()
			writeErr := writeError(t.raw, msg.Tag, t.version, boundedError(err))
			t.outMu.Unlock()
			if writeErr != nil {
				return 0, writeErr
			}
			continue
		}
		tracked.pending = pending
		t.stateMu.Lock()
		if _, exists := t.pending[msg.Tag]; exists {
			t.stateMu.Unlock()
			t.backend.Complete(t.ctx, pending, errors.New("duplicate_9p_tag"), nil)
			t.outMu.Lock()
			writeErr := writeError(t.raw, msg.Tag, t.version, "duplicate_9p_tag")
			t.outMu.Unlock()
			if writeErr != nil {
				return 0, writeErr
			}
			continue
		}
		t.pending[msg.Tag] = tracked
		t.stateMu.Unlock()
		t.readBuf = encodeMessage(msg)
	}
	n := copy(destination, t.readBuf)
	t.readBuf = t.readBuf[n:]
	return n, nil
}

func (t *backendTransport) Write(source []byte) (int, error) {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	if len(source) > 0 {
		t.writeBuf = append(t.writeBuf, source...)
	}
	for {
		if len(t.writeBuf) < 4 {
			break
		}
		size := int(binary.LittleEndian.Uint32(t.writeBuf[:4]))
		if size < 7 || size > 1<<24 {
			return len(source), fmt.Errorf("p9svc: invalid backend response size %d", size)
		}
		if len(t.writeBuf) < size {
			break
		}
		frame := append([]byte(nil), t.writeBuf[:size]...)
		t.writeBuf = t.writeBuf[size:]
		msg := message{
			Type:    frame[4],
			Tag:     binary.LittleEndian.Uint16(frame[5:7]),
			Payload: append([]byte(nil), frame[7:]...),
		}
		if err := t.processResponse(msg); err != nil {
			return len(source), err
		}
		t.outMu.Lock()
		_, err := t.raw.Write(frame)
		t.outMu.Unlock()
		if err != nil {
			return len(source), err
		}
	}
	return len(source), nil
}

func (t *backendTransport) Close() error {
	t.stateMu.Lock()
	pending := make([]trackedRequest, 0, len(t.pending))
	for _, tracked := range t.pending {
		pending = append(pending, tracked)
	}
	t.pending = make(map[uint16]trackedRequest)
	t.fids = make(map[uint32]trackedFid)
	t.stateMu.Unlock()
	for _, tracked := range pending {
		t.backend.Complete(t.ctx, tracked.pending, io.ErrUnexpectedEOF, nil)
	}
	return t.raw.Close()
}

func (t *backendTransport) describeRequest(msg message) (filebackend.Event, trackedRequest, bool) {
	attributes := map[string]string{"protocol": "9p2000", "tag": strconv.Itoa(int(msg.Tag))}
	tracked := trackedRequest{requestType: msg.Type}
	lookup := func(fid uint32) (trackedFid, bool) {
		t.stateMu.Lock()
		defer t.stateMu.Unlock()
		state, ok := t.fids[fid]
		return state, ok
	}
	setFID := func(fid uint32) trackedFid {
		state, ok := lookup(fid)
		attributes["known_fid"] = strconv.FormatBool(ok)
		return state
	}
	event := filebackend.Event{Attributes: attributes}
	switch msg.Type {
	case Tattach:
		if len(msg.Payload) < 4 {
			return event, tracked, false
		}
		tracked.fid = binary.LittleEndian.Uint32(msg.Payload[:4])
		event.Operation = filebackend.OperationAttach
		event.Directory = true
		attributes["fid"] = strconv.FormatUint(uint64(tracked.fid), 10)
	case Twalk:
		fid, newfid, names, err := decodeWalk(msg.Payload)
		if err != nil {
			return event, tracked, false
		}
		base := setFID(fid)
		tracked.fid, tracked.newfid = fid, newfid
		tracked.basePath, tracked.walkNames = base.path, names
		tracked.targetPath = joinWalk(base.path, names)
		event.Operation = filebackend.OperationWalk
		event.Path = base.path
		event.SecondaryPath = tracked.targetPath
		attributes["fid"] = strconv.FormatUint(uint64(fid), 10)
		attributes["newfid"] = strconv.FormatUint(uint64(newfid), 10)
	case Topen:
		if len(msg.Payload) < 5 {
			return event, tracked, false
		}
		fid := binary.LittleEndian.Uint32(msg.Payload[:4])
		mode := msg.Payload[4]
		state := setFID(fid)
		tracked.fid, tracked.targetPath = fid, state.path
		event.Operation = filebackend.OperationOpen
		event.Path = state.path
		event.Mode = uint32(mode)
		event.Directory = state.directory
		attributes["fid"] = strconv.FormatUint(uint64(fid), 10)
		if mode&openTrunc != 0 {
			tracked.mutationPath = []string{state.path}
		}
	case Tcreate:
		if len(msg.Payload) < 4 {
			return event, tracked, false
		}
		fid := binary.LittleEndian.Uint32(msg.Payload[:4])
		name, off, err := unpackString(msg.Payload, 4)
		if err != nil || off+5 > len(msg.Payload) {
			return event, tracked, false
		}
		perm := binary.LittleEndian.Uint32(msg.Payload[off : off+4])
		base := setFID(fid)
		target := joinRelative(base.path, name)
		tracked.fid, tracked.basePath, tracked.targetPath = fid, base.path, target
		tracked.directory = perm&permDir != 0
		tracked.mutationPath = []string{target}
		event.Operation = filebackend.OperationCreate
		event.Path = target
		event.Mode = perm
		event.Directory = tracked.directory
		attributes["fid"] = strconv.FormatUint(uint64(fid), 10)
	case Tread:
		fid, offset, count, ok := decodeIORequest(msg.Payload)
		if !ok {
			return event, tracked, false
		}
		state := setFID(fid)
		tracked.fid, tracked.targetPath = fid, state.path
		if state.directory {
			event.Operation = filebackend.OperationReadDir
		} else {
			event.Operation = filebackend.OperationRead
		}
		event.Path = state.path
		event.Offset = offset
		event.Size = uint64(count)
		event.Directory = state.directory
		attributes["fid"] = strconv.FormatUint(uint64(fid), 10)
	case Twrite:
		fid, offset, count, ok := decodeIORequest(msg.Payload)
		if !ok {
			return event, tracked, false
		}
		actual := len(msg.Payload) - 16
		if actual < 0 {
			actual = 0
		}
		if uint32(actual) < count {
			attributes["declared_size"] = strconv.FormatUint(uint64(count), 10)
			count = uint32(actual)
		}
		state := setFID(fid)
		tracked.fid, tracked.targetPath = fid, state.path
		tracked.mutationPath = []string{state.path}
		event.Operation = filebackend.OperationWrite
		event.Path = state.path
		event.Offset = offset
		event.Size = uint64(count)
		attributes["fid"] = strconv.FormatUint(uint64(fid), 10)
	case Tclunk:
		if len(msg.Payload) < 4 {
			return event, tracked, false
		}
		fid := binary.LittleEndian.Uint32(msg.Payload[:4])
		state := setFID(fid)
		tracked.fid, tracked.targetPath = fid, state.path
		event.Operation = filebackend.OperationClunk
		event.Path = state.path
		attributes["fid"] = strconv.FormatUint(uint64(fid), 10)
	case Tremove:
		if len(msg.Payload) < 4 {
			return event, tracked, false
		}
		fid := binary.LittleEndian.Uint32(msg.Payload[:4])
		state := setFID(fid)
		tracked.fid, tracked.targetPath = fid, state.path
		tracked.mutationPath = []string{state.path}
		event.Operation = filebackend.OperationRemove
		event.Path = state.path
		event.Directory = state.directory
		attributes["fid"] = strconv.FormatUint(uint64(fid), 10)
	case Tstat:
		if len(msg.Payload) < 4 {
			return event, tracked, false
		}
		fid := binary.LittleEndian.Uint32(msg.Payload[:4])
		state := setFID(fid)
		tracked.fid, tracked.targetPath = fid, state.path
		event.Operation = filebackend.OperationStat
		event.Path = state.path
		event.Directory = state.directory
		attributes["fid"] = strconv.FormatUint(uint64(fid), 10)
	default:
		return event, tracked, false
	}
	return event, tracked, true
}

func (t *backendTransport) processResponse(msg message) error {
	if msg.Type == Rversion {
		if len(msg.Payload) >= 6 {
			if version, _, err := unpackString(msg.Payload, 4); err == nil && version != "" {
				t.version = version
			}
		}
		return nil
	}
	t.stateMu.Lock()
	tracked, ok := t.pending[msg.Tag]
	if ok {
		delete(t.pending, msg.Tag)
	}
	t.stateMu.Unlock()
	if !ok {
		return nil
	}
	operationErr := responseError(msg, tracked.requestType)
	if operationErr == nil {
		t.applySuccess(msg, tracked)
	}
	if tracked.requestType == Tremove {
		t.stateMu.Lock()
		delete(t.fids, tracked.fid)
		t.stateMu.Unlock()
	}
	t.backend.Complete(t.ctx, tracked.pending, operationErr, tracked.mutationPath)
	return nil
}

func (t *backendTransport) applySuccess(msg message, tracked trackedRequest) {
	switch tracked.requestType {
	case Tattach:
		state := trackedFid{path: "", directory: true}
		t.storeFid(tracked.fid, state)
		t.observeQID("", msg.Payload, 0)
	case Twalk:
		if len(msg.Payload) < 2 {
			return
		}
		count := int(binary.LittleEndian.Uint16(msg.Payload[:2]))
		partial := partialWalk(tracked.basePath, tracked.walkNames, count)
		state := trackedFid{path: partial}
		if count == 0 && len(tracked.walkNames) == 0 {
			t.stateMu.Lock()
			state = t.fids[tracked.fid]
			t.stateMu.Unlock()
		}
		if count > 0 {
			if q, ok := decodeQID(msg.Payload, 2+(count-1)*13); ok {
				state.directory = q.typ&qidDir != 0
				t.backend.ObserveQID(partial, q.path, q.version)
			}
		}
		t.storeFid(tracked.newfid, state)
	case Topen:
		if q, ok := decodeQID(msg.Payload, 0); ok {
			t.stateMu.Lock()
			state := t.fids[tracked.fid]
			state.directory = q.typ&qidDir != 0
			t.fids[tracked.fid] = state
			t.stateMu.Unlock()
			t.backend.ObserveQID(tracked.targetPath, q.path, q.version)
		}
	case Tcreate:
		state := trackedFid{path: tracked.targetPath, directory: tracked.directory}
		if q, ok := decodeQID(msg.Payload, 0); ok {
			state.directory = q.typ&qidDir != 0
			t.backend.ObserveQID(tracked.targetPath, q.path, q.version)
		}
		t.storeFid(tracked.fid, state)
	case Tclunk:
		t.stateMu.Lock()
		delete(t.fids, tracked.fid)
		t.stateMu.Unlock()
	}
}

func (t *backendTransport) storeFid(fid uint32, state trackedFid) {
	t.stateMu.Lock()
	t.fids[fid] = state
	t.stateMu.Unlock()
}

func (t *backendTransport) observeQID(relative string, payload []byte, offset int) {
	if q, ok := decodeQID(payload, offset); ok {
		t.backend.ObserveQID(relative, q.path, q.version)
	}
}

type decodedQID struct {
	typ     uint8
	version uint32
	path    uint64
}

func decodeQID(payload []byte, offset int) (decodedQID, bool) {
	if offset < 0 || offset+13 > len(payload) {
		return decodedQID{}, false
	}
	return decodedQID{
		typ:     payload[offset],
		version: binary.LittleEndian.Uint32(payload[offset+1 : offset+5]),
		path:    binary.LittleEndian.Uint64(payload[offset+5 : offset+13]),
	}, true
}

func decodeWalk(payload []byte) (uint32, uint32, []string, error) {
	if len(payload) < 10 {
		return 0, 0, nil, errors.New("short_twalk")
	}
	fid := binary.LittleEndian.Uint32(payload[:4])
	newfid := binary.LittleEndian.Uint32(payload[4:8])
	count := int(binary.LittleEndian.Uint16(payload[8:10]))
	offset := 10
	names := make([]string, 0, count)
	for index := 0; index < count; index++ {
		name, next, err := unpackString(payload, offset)
		if err != nil {
			return 0, 0, nil, err
		}
		offset = next
		names = append(names, name)
	}
	return fid, newfid, names, nil
}

func decodeIORequest(payload []byte) (uint32, uint64, uint32, bool) {
	if len(payload) < 16 {
		return 0, 0, 0, false
	}
	return binary.LittleEndian.Uint32(payload[:4]), binary.LittleEndian.Uint64(payload[4:12]), binary.LittleEndian.Uint32(payload[12:16]), true
}

func responseError(msg message, requestType uint8) error {
	if msg.Type == Rerror {
		message, _, err := unpackString(msg.Payload, 0)
		if err != nil || message == "" {
			message = "9p_backend_error"
		}
		return errors.New(message)
	}
	if msg.Type != expectedResponse(requestType) {
		return fmt.Errorf("unexpected_9p_response_%d", msg.Type)
	}
	return nil
}

func expectedResponse(request uint8) uint8 {
	switch request {
	case Tattach:
		return Rattach
	case Twalk:
		return Rwalk
	case Topen:
		return Ropen
	case Tcreate:
		return Rcreate
	case Tread:
		return Rread
	case Twrite:
		return Rwrite
	case Tclunk:
		return Rclunk
	case Tremove:
		return Rremove
	case Tstat:
		return Rstat
	default:
		return 0
	}
}

func encodeMessage(msg message) []byte {
	frame := make([]byte, 7+len(msg.Payload))
	binary.LittleEndian.PutUint32(frame[:4], uint32(len(frame)))
	frame[4] = msg.Type
	binary.LittleEndian.PutUint16(frame[5:7], msg.Tag)
	copy(frame[7:], msg.Payload)
	return frame
}

func joinWalk(base string, names []string) string {
	result := base
	for _, name := range names {
		if name == "" || name == "." {
			continue
		}
		result = joinRelative(result, name)
	}
	return result
}

func partialWalk(base string, names []string, qidCount int) string {
	result := base
	used := 0
	for _, name := range names {
		if name == "" || name == "." {
			continue
		}
		if used >= qidCount {
			break
		}
		result = joinRelative(result, name)
		used++
	}
	return result
}

func joinRelative(base, name string) string {
	joined := path.Join(strings.TrimPrefix(base, "/"), name)
	if joined == "." {
		return ""
	}
	return strings.TrimPrefix(joined, "/")
}

func boundedError(err error) string {
	if err == nil {
		return "file_backend_denied"
	}
	message := err.Error()
	if len(message) > 4096 {
		message = message[:4096]
	}
	return message
}

var _ io.ReadWriteCloser = (*backendTransport)(nil)
