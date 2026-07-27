package mapreduce

import (
	"context"
	"errors"
	"strings"
	"time"

	"weaverssh/sessionbroker"
	"weaverssh/sessionmux"
)

type Caller interface {
	Call(context.Context, string, Request) (Response, error)
}

// BrokerClient invokes the map/reduce ServiceExec protocol through the active
// same-user session broker. The broker replaces caller provenance before routing.
type BrokerClient struct {
	Socket string
}

func (c BrokerClient) Call(ctx context.Context, target string, request Request) (Response, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	socket := strings.TrimSpace(c.Socket)
	target = strings.TrimSpace(target)
	if socket == "" || target == "" {
		return Response{}, errors.New("mapreduce: incomplete broker client")
	}
	if request.ID == "" {
		request.ID = NewJobID()
	}
	metadata, err := NewOpenMetadata(target)
	if err != nil {
		return Response{}, err
	}
	stream, err := sessionbroker.Dial(ctx, "unix", socket, sessionbroker.OpenRequest{
		Node:    target,
		Service: sessionmux.ServiceExec,
		Data:    metadata,
	})
	if err != nil {
		return Response{}, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetDeadline(deadline)
		defer stream.SetDeadline(time.Time{})
	}
	return CallStream(ctx, stream, request)
}

var _ Caller = BrokerClient{}
