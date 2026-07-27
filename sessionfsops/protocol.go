// Package sessionfsops provides bounded filesystem metadata and mutation calls
// over an already authorized ServiceFS stream. Ordinary ServiceFS streams with
// empty metadata remain 9P2000 transports.
package sessionfsops

import (
	"bufio"
	"bytes"
	stdjson "encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	ProtocolVersion = "weaverssh.fs-ops.v1"
	MaxMessageBytes = 1 << 20
	OperationPrepareReplace = "prepare-replace"
	OperationCommitReplace = "commit-replace"
	OperationAbortReplace = "abort-replace"
	OperationLstat = "lstat"
	OperationList = "list"
	OperationSymlink = "symlink"
	OperationSetMetadata = "set-metadata"
	OperationPrepareTree = "prepare-tree"
	OperationCommitTree = "commit-tree"
	OperationAbortTree = "abort-tree"
)

var (
	ErrWrongProtocol = errors.New("sessionfsops: wrong protocol")
	ErrInvalidRequest = errors.New("sessionfsops: invalid request")
	ErrReadOnly = errors.New("sessionfsops: filesystem is read-only")
	ErrPathDenied = errors.New("sessionfsops: path denied")
	ErrReplaceFailed = errors.New("sessionfsops: replacement failed")
)

type Request struct {
	Protocol string `json:"protocol"`
	ID string `json:"id"`
	Operation string `json:"operation"`
	FinalPath string `json:"final_path,omitempty"`
	TempPath string `json:"temp_path,omitempty"`
	Mode uint32 `json:"mode,omitempty"`
	PreserveExistingMode bool `json:"preserve_existing_mode,omitempty"`
	ReplaceExisting bool `json:"replace_existing,omitempty"`
	LinkTarget string `json:"link_target,omitempty"`
	ModTimeUnixNano int64 `json:"mod_time_unix_nano,omitempty"`
	Cursor string `json:"cursor,omitempty"`
	Limit int `json:"limit,omitempty"`
}

type FileMetadata struct {
	Path string `json:"path"`
	Name string `json:"name"`
	Type string `json:"type"`
	Mode uint32 `json:"mode"`
	Size int64 `json:"size"`
	ModTimeUnixNano int64 `json:"mod_time_unix_nano"`
	LinkTarget string `json:"link_target,omitempty"`
}

type Result struct {
	TempPath string `json:"temp_path,omitempty"`
	BackupPath string `json:"backup_path,omitempty"`
	AppliedMode uint32 `json:"applied_mode,omitempty"`
	ReplacedExisting bool `json:"replaced_existing,omitempty"`
	AtomicVisibility bool `json:"atomic_visibility,omitempty"`
	RollbackPerformed bool `json:"rollback_performed,omitempty"`
	Metadata *FileMetadata `json:"metadata,omitempty"`
	Entries []FileMetadata `json:"entries,omitempty"`
	NextCursor string `json:"next_cursor,omitempty"`
}

type Error struct { Code string `json:"code"`; Message string `json:"message"` }
type Response struct { Protocol string `json:"protocol"`; ID string `json:"id"`; Result Result `json:"result,omitempty"`; Error *Error `json:"error,omitempty"` }

func MetadataBytes() []byte { return []byte(ProtocolVersion) }
func Metadata() []byte { return MetadataBytes() }
func IsMetadata(payload []byte) bool { return string(payload) == ProtocolVersion }

func validateRequest(request Request) error {
	if strings.TrimSpace(request.Protocol) != ProtocolVersion || strings.TrimSpace(request.ID) == "" || len(request.ID) > 128 { return ErrInvalidRequest }
	switch strings.TrimSpace(request.Operation) {
	case OperationPrepareReplace:
		if request.FinalPath == "" || request.TempPath != "" { return ErrInvalidRequest }
	case OperationCommitReplace:
		if request.FinalPath == "" || request.TempPath == "" { return ErrInvalidRequest }
	case OperationAbortReplace:
		if request.TempPath == "" { return ErrInvalidRequest }
	case OperationLstat:
		if request.FinalPath == "" { return ErrInvalidRequest }
	case OperationList:
		if request.FinalPath == "" || request.Limit < 0 || request.Limit > 1024 { return ErrInvalidRequest }
	case OperationSymlink:
		if request.FinalPath == "" || request.LinkTarget == "" { return ErrInvalidRequest }
	case OperationSetMetadata:
		if request.FinalPath == "" || (request.Mode == 0 && request.ModTimeUnixNano == 0) { return ErrInvalidRequest }
	case OperationPrepareTree:
		if request.FinalPath == "" || request.TempPath != "" { return ErrInvalidRequest }
	case OperationCommitTree:
		if request.FinalPath == "" || request.TempPath == "" { return ErrInvalidRequest }
	case OperationAbortTree:
		if request.TempPath == "" { return ErrInvalidRequest }
	default:
		return ErrInvalidRequest
	}
	return nil
}

func readRequest(reader io.Reader) (Request, error) {
	payload, err := readMessage(reader)
	if err != nil { return Request{}, fmt.Errorf("%w: %v", ErrInvalidRequest, err) }
	var request Request
	decoder := stdjson.NewDecoder(bytes.NewReader(payload)); decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil { return Request{}, fmt.Errorf("%w: %v", ErrInvalidRequest, err) }
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) { return Request{}, ErrInvalidRequest }
	if err := validateRequest(request); err != nil { return Request{}, err }
	return request, nil
}

func writeRequest(writer io.Writer, request Request) error { request.Protocol = ProtocolVersion; payload, err := stdjson.Marshal(request); if err != nil { return err }; return writeMessage(writer, payload) }

func readResponse(reader io.Reader) (Response, error) {
	payload, err := readMessage(reader); if err != nil { return Response{}, err }
	var response Response
	decoder := stdjson.NewDecoder(bytes.NewReader(payload)); decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil { return Response{}, err }
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) { return Response{}, ErrInvalidRequest }
	if response.Protocol != ProtocolVersion { return Response{}, ErrWrongProtocol }
	if response.Error != nil { return response, fmt.Errorf("sessionfsops %s: %s", response.Error.Code, response.Error.Message) }
	return response, nil
}

func writeResponse(writer io.Writer, response Response) error { response.Protocol = ProtocolVersion; payload, err := stdjson.Marshal(response); if err != nil { return err }; return writeMessage(writer, payload) }

func readMessage(reader io.Reader) ([]byte, error) {
	limited := &io.LimitedReader{R: reader, N: MaxMessageBytes + 2}
	line, err := bufio.NewReader(limited).ReadBytes('\n'); if err != nil { return nil, err }
	if len(line) == 0 || len(line) > MaxMessageBytes+1 || line[len(line)-1] != '\n' { return nil, errors.New("invalid bounded message") }
	line = bytes.TrimSpace(line); if len(line) == 0 { return nil, errors.New("empty message") }
	return line, nil
}

func writeMessage(writer io.Writer, payload []byte) error {
	if len(payload) == 0 || len(payload)+1 > MaxMessageBytes { return errors.New("sessionfsops: message too large") }
	payload = append(append([]byte(nil), payload...), '\n')
	for len(payload) > 0 { n, err := writer.Write(payload); if err != nil { return err }; if n == 0 { return io.ErrShortWrite }; payload = payload[n:] }
	return nil
}

func errorResponse(id string, err error) Response {
	code := "internal"
	switch { case errors.Is(err, ErrWrongProtocol): code = "wrong_protocol"; case errors.Is(err, ErrInvalidRequest): code = "invalid_request"; case errors.Is(err, ErrReadOnly): code = "read_only"; case errors.Is(err, ErrPathDenied): code = "path_denied"; case errors.Is(err, ErrReplaceFailed): code = "replace_failed" }
	return Response{ID: id, Error: &Error{Code: code, Message: err.Error()}}
}
