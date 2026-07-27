package pubsub

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

const (
	ComponentVFS = "vfs"

	FileTransferEventPrefix = "file_transfer"
)

type FileTransferPhase string

type FileTransferDirection string

const (
	FileTransferStarted   FileTransferPhase = "started"
	FileTransferProgress  FileTransferPhase = "progress"
	FileTransferCompleted FileTransferPhase = "completed"
	FileTransferFailed    FileTransferPhase = "failed"

	TransferVfsToLocal FileTransferDirection = "vfs_to_local"
	TransferLocalToVfs FileTransferDirection = "local_to_vfs"
	TransferVfsToVfs   FileTransferDirection = "vfs_to_vfs"
	TransferLocal      FileTransferDirection = "local"
)

// FileTransfer is metadata for a file-transfer event. It intentionally excludes
// payload bytes. Hooks see paths, direction, protocol, status, and counters only.
type FileTransfer struct {
	ID              string                `json:"id"`
	Operation       string                `json:"operation"`
	Direction       FileTransferDirection `json:"direction"`
	Source          string                `json:"source"`
	Destination     string                `json:"destination"`
	SourceView      string                `json:"source_view,omitempty"`
	DestinationView string                `json:"destination_view,omitempty"`
	Protocol        string                `json:"protocol,omitempty"`
	Bytes           int64                 `json:"bytes,omitempty"`
	Files           int64                 `json:"files,omitempty"`
	Status          string                `json:"status,omitempty"`
	Error           string                `json:"error,omitempty"`
}

func (t FileTransfer) Normalized() FileTransfer {
	t.ID = strings.TrimSpace(t.ID)
	if t.ID == "" {
		t.ID = newID("file-transfer")
	}
	t.Operation = strings.TrimSpace(t.Operation)
	if t.Operation == "" {
		t.Operation = "transfer"
	}
	t.Direction = FileTransferDirection(strings.TrimSpace(string(t.Direction)))
	if t.Direction == "" {
		t.Direction = TransferLocal
	}
	t.Source = strings.TrimSpace(t.Source)
	t.Destination = strings.TrimSpace(t.Destination)
	t.SourceView = strings.TrimSpace(t.SourceView)
	t.DestinationView = strings.TrimSpace(t.DestinationView)
	t.Protocol = strings.TrimSpace(t.Protocol)
	t.Status = strings.TrimSpace(t.Status)
	t.Error = strings.TrimSpace(t.Error)
	if t.Bytes < 0 {
		t.Bytes = 0
	}
	if t.Files < 0 {
		t.Files = 0
	}
	return t
}

func (t FileTransfer) Validate() error {
	t = t.Normalized()
	if t.Source == "" {
		return fmt.Errorf("file transfer source is required")
	}
	if t.Destination == "" {
		return fmt.Errorf("file transfer destination is required")
	}
	return nil
}

func (t FileTransfer) Fields() map[string]string {
	t = t.Normalized()
	fields := map[string]string{
		"transfer_id": t.ID,
		"operation":   t.Operation,
		"direction":   string(t.Direction),
		"source":      t.Source,
		"destination": t.Destination,
	}
	if t.SourceView != "" {
		fields["source_view"] = t.SourceView
	}
	if t.DestinationView != "" {
		fields["destination_view"] = t.DestinationView
	}
	if t.Protocol != "" {
		fields["protocol"] = t.Protocol
	}
	if t.Bytes > 0 {
		fields["bytes"] = strconv.FormatInt(t.Bytes, 10)
	}
	if t.Files > 0 {
		fields["files"] = strconv.FormatInt(t.Files, 10)
	}
	if t.Status != "" {
		fields["status"] = t.Status
	}
	if t.Error != "" {
		fields["error"] = t.Error
	}
	return fields
}

func FileTransferEventType(phase FileTransferPhase) string {
	phase = FileTransferPhase(strings.TrimSpace(string(phase)))
	if phase == "" {
		phase = FileTransferProgress
	}
	return FileTransferEventPrefix + "_" + string(phase)
}

func NewFileTransferEvent(phase FileTransferPhase, transfer FileTransfer) Event {
	transfer = transfer.Normalized()
	transfer.Status = string(phase)
	message := fmt.Sprintf("file transfer %s", phase)
	return NewEventFrom(EventOriginInternal, FileTransferEventType(phase), ComponentVFS, message, transfer.Fields())
}

func (a *API) EmitFileTransfer(ctx context.Context, phase FileTransferPhase, transfer FileTransfer) (HookedEmitResult, error) {
	if err := transfer.Validate(); err != nil {
		return HookedEmitResult{}, err
	}
	return a.EmitEvent(ctx, NewFileTransferEvent(phase, transfer))
}

func (a *API) DispatchFileTransfer(ctx context.Context, point HookPoint, phase FileTransferPhase, transfer FileTransfer) (HookDispatch, error) {
	if err := transfer.Validate(); err != nil {
		return HookDispatch{}, err
	}
	event := NewFileTransferEvent(phase, transfer)
	topic, err := a.TopicFor(event)
	if err != nil {
		return HookDispatch{}, err
	}
	return a.Dispatch(ctx, point, topic, event)
}

func (a *API) BeforeFileTransfer(ctx context.Context, transfer FileTransfer) (HookDispatch, error) {
	return a.DispatchFileTransfer(ctx, HookBeforeFileTransfer, FileTransferStarted, transfer)
}

func (a *API) AfterFileTransfer(ctx context.Context, phase FileTransferPhase, transfer FileTransfer) (HookDispatch, error) {
	return a.DispatchFileTransfer(ctx, HookAfterFileTransfer, phase, transfer)
}

func (a *API) ObserveFileTransferProgress(ctx context.Context, transfer FileTransfer) (HookDispatch, error) {
	return a.DispatchFileTransfer(ctx, HookOnFileTransferProgress, FileTransferProgress, transfer)
}
