package sessionfsops

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"weaverssh/sessionbroker"
	"weaverssh/sessionmux"
)

type Client struct { Socket string; Node string }

func (c Client) PrepareReplace(ctx context.Context, finalPath string, mode uint32, preserveExistingMode bool) (Result, error) {
	return c.call(ctx, Request{Operation: OperationPrepareReplace, FinalPath: finalPath, Mode: mode, PreserveExistingMode: preserveExistingMode})
}
func (c Client) CommitReplace(ctx context.Context, tempPath, finalPath string) error { _, err := c.call(ctx, Request{Operation: OperationCommitReplace, TempPath: tempPath, FinalPath: finalPath}); return err }
func (c Client) AbortReplace(ctx context.Context, tempPath string) error { _, err := c.call(ctx, Request{Operation: OperationAbortReplace, TempPath: tempPath}); return err }

func (c Client) Lstat(ctx context.Context, path string) (FileMetadata, error) {
	result, err := c.call(ctx, Request{Operation: OperationLstat, FinalPath: path})
	if err != nil { return FileMetadata{}, err }
	if result.Metadata == nil { return FileMetadata{}, errors.New("sessionfsops: missing lstat metadata") }
	return *result.Metadata, nil
}

func (c Client) List(ctx context.Context, path, cursor string, limit int) ([]FileMetadata, string, error) {
	result, err := c.call(ctx, Request{Operation: OperationList, FinalPath: path, Cursor: cursor, Limit: limit})
	if err != nil { return nil, "", err }
	return result.Entries, result.NextCursor, nil
}

func (c Client) ListAll(ctx context.Context, path string) ([]FileMetadata, error) {
	var out []FileMetadata
	cursor := ""
	for {
		entries, next, err := c.List(ctx, path, cursor, 256)
		if err != nil { return nil, err }
		out = append(out, entries...)
		if next == "" { return out, nil }
		if next == cursor { return nil, errors.New("sessionfsops: list cursor did not advance") }
		cursor = next
	}
}

func (c Client) Symlink(ctx context.Context, path, target string, replace bool) error {
	_, err := c.call(ctx, Request{Operation: OperationSymlink, FinalPath: path, LinkTarget: target, ReplaceExisting: replace})
	return err
}

func (c Client) SetMetadata(ctx context.Context, path string, mode uint32, modTime time.Time) error {
	var nanos int64
	if !modTime.IsZero() { nanos = modTime.UnixNano() }
	_, err := c.call(ctx, Request{Operation: OperationSetMetadata, FinalPath: path, Mode: mode, ModTimeUnixNano: nanos})
	return err
}

func (c Client) PrepareTree(ctx context.Context, finalPath string, mode uint32, replace bool) (Result, error) {
	return c.call(ctx, Request{Operation: OperationPrepareTree, FinalPath: finalPath, Mode: mode, ReplaceExisting: replace})
}

func (c Client) CommitTree(ctx context.Context, tempPath, finalPath string, replace bool) (Result, error) {
	return c.call(ctx, Request{Operation: OperationCommitTree, TempPath: tempPath, FinalPath: finalPath, ReplaceExisting: replace})
}

func (c Client) AbortTree(ctx context.Context, tempPath string) error {
	_, err := c.call(ctx, Request{Operation: OperationAbortTree, TempPath: tempPath})
	return err
}

func (c Client) call(ctx context.Context, request Request) (Result, error) {
	if strings.TrimSpace(c.Socket) == "" || strings.TrimSpace(c.Node) == "" { return Result{}, errors.New("sessionfsops: incomplete client") }
	request.Protocol = ProtocolVersion
	request.ID = randomID()
	stream, err := sessionbroker.Dial(ctx, "unix", c.Socket, sessionbroker.OpenRequest{Node: strings.TrimSpace(c.Node), Service: sessionmux.ServiceFS, Data: Metadata()})
	if err != nil { return Result{}, fmt.Errorf("sessionfsops: open routed operation stream: %w", err) }
	defer stream.Close()
	if deadline, ok := ctx.Deadline(); ok { _ = stream.SetDeadline(deadline); defer stream.SetDeadline(time.Time{}) }
	if err := writeRequest(stream, request); err != nil { return Result{}, err }
	response, err := readResponse(stream); if err != nil { return Result{}, err }
	if response.ID != request.ID { return Result{}, errors.New("sessionfsops: response ID mismatch") }
	return response.Result, nil
}

func randomID() string {
	payload := make([]byte, 12)
	if _, err := rand.Read(payload); err != nil { return "fsops-request" }
	return hex.EncodeToString(payload)
}
