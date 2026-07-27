package sessioncontrol

import (
	"context"
	"errors"
	"fmt"

	"weaverssh/sessionmux"
)

// PendingTarget is a dispatcher-accepted target whose metadata has been parsed
// but whose second-stage acknowledgement has not yet been sent.
type PendingTarget struct {
	Stream   *sessionmux.Stream
	NodeRef  string
	Service  sessionmux.ServiceID
	Data     []byte
}

// InspectAcceptedTarget parses one already accepted target without authorizing or
// acknowledging it. Routers use this to establish the downstream stream first.
func InspectAcceptedTarget(stream *sessionmux.Stream) (PendingTarget, error) {
	if stream == nil {
		return PendingTarget{}, errors.New("sessioncontrol: nil accepted stream")
	}
	if stream.Service() == sessionmux.ServiceControl {
		_ = stream.Reset()
		return PendingTarget{}, ErrUnexpectedControl
	}
	metadata, err := DecodeOpenMetadata(stream.Metadata())
	if err != nil {
		_ = stream.Reset()
		return PendingTarget{}, err
	}
	return PendingTarget{
		Stream:  stream,
		NodeRef: metadata.Node,
		Service: stream.Service(),
		Data:    append([]byte(nil), metadata.Data...),
	}, nil
}

// AcknowledgePendingTarget sends the existing second-stage target acknowledgement.
// Callers must invoke this only after the local implementation or complete
// downstream route has accepted the target.
func AcknowledgePendingTarget(ctx context.Context, pending PendingTarget) error {
	if pending.Stream == nil {
		return errors.New("sessioncontrol: nil pending target")
	}
	select {
	case <-ctx.Done():
		_ = pending.Stream.Reset()
		return ctx.Err()
	default:
	}
	if _, err := pending.Stream.Write(targetAcceptedMessage); err != nil {
		_ = pending.Stream.Reset()
		return fmt.Errorf("sessioncontrol: acknowledge target: %w", err)
	}
	return nil
}
