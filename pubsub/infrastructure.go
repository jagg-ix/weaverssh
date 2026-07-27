package pubsub

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

const (
	ComponentInfrastructure = "infrastructure"
	FileOperationKind       = "file"
)

type FileOperation string

const (
	FileCreated FileOperation = "file_created"
	FileRemoved FileOperation = "file_removed"
	FileOpened  FileOperation = "file_opened"
	FileRead    FileOperation = "file_read"
	FileWritten FileOperation = "file_written"
	FileClosed  FileOperation = "file_closed"
	FileListed  FileOperation = "file_listed"
	FileStat    FileOperation = "file_stat"
	FileMkdir   FileOperation = "file_mkdir"
)

// FileEvent is metadata for a file-related infrastructure operation. It does
// not include file payload bytes; hooks and rules only receive paths, protocol,
// status, counters, and caller-provided metadata.
type FileEvent struct {
	ID        string            `json:"id,omitempty"`
	Path      string            `json:"path"`
	ViewPath  string            `json:"view_path,omitempty"`
	Component string            `json:"component,omitempty"`
	Origin    EventOrigin       `json:"origin,omitempty"`
	Protocol  string            `json:"protocol,omitempty"`
	Subsystem string            `json:"subsystem,omitempty"`
	Bytes     int64             `json:"bytes,omitempty"`
	Files     int64             `json:"files,omitempty"`
	IsDir     bool              `json:"is_dir,omitempty"`
	Status    string            `json:"status,omitempty"`
	Error     string            `json:"error,omitempty"`
	Fields    map[string]string `json:"fields,omitempty"`
}

func (f FileEvent) Normalized() FileEvent {
	f.ID = strings.TrimSpace(f.ID)
	if f.ID == "" {
		f.ID = newID("file-operation")
	}
	f.Path = strings.TrimSpace(f.Path)
	f.ViewPath = strings.TrimSpace(f.ViewPath)
	f.Component = strings.TrimSpace(f.Component)
	if f.Component == "" {
		f.Component = ComponentInfrastructure
	}
	f.Origin = normalizeEventOrigin(f.Origin)
	f.Protocol = strings.TrimSpace(f.Protocol)
	f.Subsystem = strings.TrimSpace(f.Subsystem)
	if f.Subsystem == "" {
		f.Subsystem = "filesystem"
	}
	f.Status = strings.TrimSpace(f.Status)
	f.Error = strings.TrimSpace(f.Error)
	if f.Bytes < 0 {
		f.Bytes = 0
	}
	if f.Files < 0 {
		f.Files = 0
	}
	f.Fields = copyFields(f.Fields)
	return f
}

func (f FileEvent) Validate(operation FileOperation) error {
	operation = FileOperation(strings.TrimSpace(string(operation)))
	if operation == "" {
		return fmt.Errorf("file operation is required")
	}
	f = f.Normalized()
	if f.Path == "" {
		return fmt.Errorf("file event path is required")
	}
	return nil
}

func (f FileEvent) FieldsFor(operation FileOperation) map[string]string {
	f = f.Normalized()
	operation = FileOperation(strings.TrimSpace(string(operation)))
	fields := map[string]string{
		"file_id":   f.ID,
		"kind":      FileOperationKind,
		"operation": string(operation),
		"path":      f.Path,
		"subsystem": f.Subsystem,
		"is_dir":    strconv.FormatBool(f.IsDir),
	}
	if f.ViewPath != "" {
		fields["view_path"] = f.ViewPath
	}
	if f.Protocol != "" {
		fields["protocol"] = f.Protocol
	}
	if f.Bytes > 0 {
		fields["bytes"] = strconv.FormatInt(f.Bytes, 10)
	}
	if f.Files > 0 {
		fields["files"] = strconv.FormatInt(f.Files, 10)
	}
	if f.Status != "" {
		fields["status"] = f.Status
	}
	if f.Error != "" {
		fields["error"] = f.Error
	}
	for k, v := range f.Fields {
		if _, exists := fields[k]; !exists {
			fields[k] = v
		}
	}
	return fields
}

func NewFileEvent(operation FileOperation, file FileEvent) Event {
	file = file.Normalized()
	message := fmt.Sprintf("file operation %s", strings.TrimSpace(string(operation)))
	if file.Path != "" {
		message += " " + file.Path
	}
	return NewEventFrom(file.Origin, strings.TrimSpace(string(operation)), file.Component, message, file.FieldsFor(operation))
}

func (a *API) EmitFileEvent(ctx context.Context, operation FileOperation, file FileEvent) (HookedEmitResult, error) {
	if err := file.Validate(operation); err != nil {
		return HookedEmitResult{}, err
	}
	return a.EmitEvent(ctx, NewFileEvent(operation, file))
}

func (a *API) DispatchFileEvent(ctx context.Context, point HookPoint, operation FileOperation, file FileEvent) (HookDispatch, error) {
	if err := file.Validate(operation); err != nil {
		return HookDispatch{}, err
	}
	event := NewFileEvent(operation, file)
	topic, err := a.TopicFor(event)
	if err != nil {
		return HookDispatch{}, err
	}
	return a.Dispatch(ctx, point, topic, event)
}

func (a *API) BeforeFileOperation(ctx context.Context, operation FileOperation, file FileEvent) (HookDispatch, error) {
	return a.DispatchFileEvent(ctx, HookBeforeFileOperation, operation, file)
}

func (a *API) AfterFileOperation(ctx context.Context, operation FileOperation, file FileEvent) (HookDispatch, error) {
	return a.DispatchFileEvent(ctx, HookAfterFileOperation, operation, file)
}

func (a *API) ObserveFileOperation(ctx context.Context, operation FileOperation, file FileEvent) (HookDispatch, error) {
	return a.DispatchFileEvent(ctx, HookOnFileOperation, operation, file)
}

func (a *API) RunFileOperation(ctx context.Context, operation FileOperation, file FileEvent, fn HookedOperation) (HookedOperationResult, error) {
	if err := file.Validate(operation); err != nil {
		return HookedOperationResult{}, err
	}
	event := NewFileEvent(operation, file)
	topic, err := a.TopicFor(event)
	if err != nil {
		return HookedOperationResult{}, err
	}
	return a.runHookedOperation(ctx, HookBeforeFileOperation, HookAfterFileOperation, topic, event, fn)
}
