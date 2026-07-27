package vfscli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"weaverssh/pubsub"
)

const envInfraEvents = "WEAVERSSH_INFRA_EVENTS"

type transferObserver struct {
	api    *pubsub.API
	closer func() error
}

type jsonlEventPublisher struct {
	mu sync.Mutex
	f  *os.File
}

// newTransferObserver returns a file-transfer event observer that appends
// JSONL events to path. An empty path yields a nil observer, in which case
// operations run without instrumentation.
func newTransferObserver(path string) (*transferObserver, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	api := pubsub.NewAPI(pubsub.APIConfig{Publisher: &jsonlEventPublisher{f: file}})
	return &transferObserver{api: api, closer: file.Close}, nil
}

func newInfrastructureObserver() (*transferObserver, error) {
	return newTransferObserver(envOr(envInfraEvents, ""))
}

func (p *jsonlEventPublisher) PublishEvent(prefix string, event pubsub.Event) (string, error) {
	topic, err := pubsub.EventTopic(prefix, event.Component, event.Type)
	if err != nil {
		return "", err
	}
	payload, err := event.JSON()
	if err != nil {
		return "", err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, err := p.f.Write(append(payload, '\n')); err != nil {
		return "", err
	}
	return topic, nil
}

func (o *transferObserver) Close() error {
	if o == nil || o.closer == nil {
		return nil
	}
	return o.closer()
}

func (o *transferObserver) run(ctx context.Context, transfer pubsub.FileTransfer, fn func(*pubsub.FileTransfer) error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	transfer = transfer.Normalized()
	if o == nil || o.api == nil {
		return fn(&transfer)
	}
	before, err := o.api.BeforeFileTransfer(ctx, transfer)
	if err != nil {
		return err
	}
	if before.Dropped {
		return pubsub.ErrEventDropped
	}
	_, _ = o.api.EmitFileTransfer(ctx, pubsub.FileTransferStarted, transfer)
	o.emitFileOperation(ctx, pubsub.FileOpened, fileEventFromTransfer(transfer, true, string(pubsub.FileTransferStarted)))
	if err := fn(&transfer); err != nil {
		transfer.Error = err.Error()
		transfer.Status = string(pubsub.FileTransferFailed)
		o.emitFileOperation(ctx, sourceOperationForTransfer(transfer), fileEventFromTransfer(transfer, true, string(pubsub.FileTransferFailed)))
		_, _ = o.api.EmitFileTransfer(ctx, pubsub.FileTransferFailed, transfer)
		_, _ = o.api.AfterFileTransfer(ctx, pubsub.FileTransferFailed, transfer)
		return err
	}
	transfer.Status = string(pubsub.FileTransferCompleted)
	if transfer.Files == 0 {
		transfer.Files = 1
	}
	o.emitFileOperation(ctx, pubsub.FileRead, fileEventFromTransfer(transfer, true, string(pubsub.FileTransferCompleted)))
	o.emitFileOperation(ctx, destinationOperationForTransfer(transfer), fileEventFromTransfer(transfer, false, string(pubsub.FileTransferCompleted)))
	if _, err := o.api.EmitFileTransfer(ctx, pubsub.FileTransferCompleted, transfer); err != nil {
		return err
	}
	if dispatch, err := o.api.AfterFileTransfer(ctx, pubsub.FileTransferCompleted, transfer); err != nil {
		return err
	} else if dispatch.Dropped {
		return fmt.Errorf("file transfer after hook dropped event")
	}
	return nil
}

func (o *transferObserver) emitFileOperation(ctx context.Context, operation pubsub.FileOperation, file pubsub.FileEvent) {
	if o == nil || o.api == nil || file.Path == "" {
		return
	}
	_, _ = o.api.EmitFileEvent(ctx, operation, file)
}

func sourceOperationForTransfer(pubsub.FileTransfer) pubsub.FileOperation {
	return pubsub.FileRead
}

func destinationOperationForTransfer(pubsub.FileTransfer) pubsub.FileOperation {
	return pubsub.FileWritten
}

func fileEventFromTransfer(transfer pubsub.FileTransfer, source bool, status string) pubsub.FileEvent {
	transfer = transfer.Normalized()
	path := transfer.Destination
	viewPath := transfer.DestinationView
	if source {
		path = transfer.Source
		viewPath = transfer.SourceView
	}
	file := pubsub.FileEvent{
		Path:      path,
		ViewPath:  viewPath,
		Component: pubsub.ComponentVFS,
		Protocol:  transfer.Protocol,
		Subsystem: "vfs",
		Bytes:     transfer.Bytes,
		Files:     transfer.Files,
		Status:    status,
		Fields: map[string]string{
			"transfer_id": transfer.ID,
			"direction":   string(transfer.Direction),
			"source":      transfer.Source,
			"destination": transfer.Destination,
		},
	}
	if transfer.Error != "" {
		file.Error = transfer.Error
	}
	return file
}
