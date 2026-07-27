package socketcontrol

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestServerVerifyRejectsReplayAndExpiredRequest(t *testing.T) {
	token, err := NewToken(); if err != nil { t.Fatal(err) }
	server := &Server{Token: token, MaxSkew: 10 * time.Second, Handler: func(context.Context, Request) (any, error) { return nil, nil }}
	now := time.Unix(1700000000, 0)
	request, err := NewRequest(ActionStatus, "", token, now); if err != nil { t.Fatal(err) }
	if err := server.verify(request, now); err != nil { t.Fatal(err) }
	if err := server.verify(request, now); !errors.Is(err, ErrReplay) { t.Fatalf("replay error=%v", err) }
	expired, err := NewRequest(ActionStatus, "", token, now.Add(-time.Minute)); if err != nil { t.Fatal(err) }
	if err := server.verify(expired, now); !errors.Is(err, ErrUnauthorized) { t.Fatalf("expired error=%v", err) }
	forged := request; forged.Nonce = "new-nonce"
	if err := server.verify(forged, now); !errors.Is(err, ErrUnauthorized) { t.Fatalf("forged error=%v", err) }
}

func TestAuthenticatedCallRoundTrip(t *testing.T) {
	token, err := NewToken(); if err != nil { t.Fatal(err) }
	listener, err := net.Listen("tcp", "127.0.0.1:0"); if err != nil { t.Fatal(err) }
	ctx, cancel := context.WithCancel(context.Background()); defer cancel()
	server := &Server{Token: token, Handler: func(_ context.Context, request Request) (any, error) {
		return map[string]any{"action": request.Action, "generation": 3}, nil
	}}
	done := make(chan error, 1); go func() { done <- server.Serve(ctx, listener) }()
	callCtx, callCancel := context.WithTimeout(context.Background(), time.Second); defer callCancel()
	response, err := Call(callCtx, "tcp", listener.Addr().String(), token, ActionStatus, ""); if err != nil { t.Fatal(err) }
	var payload struct { Action string `json:"action"`; Generation int `json:"generation"` }
	if err := DecodePayload(response, &payload); err != nil { t.Fatal(err) }
	if payload.Action != ActionStatus || payload.Generation != 3 { t.Fatalf("payload=%+v", payload) }

	wrong, _ := NewToken()
	if _, err := Call(callCtx, "tcp", listener.Addr().String(), wrong, ActionStatus, ""); err == nil { t.Fatal("wrong token accepted") }
	cancel(); _ = listener.Close(); <-done
}
