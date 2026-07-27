package sessionbroker

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"

	"weaverssh/sessionmux"
)

func TestRouterUsesCurrentBindingAndIgnoresStaleCleanup(t *testing.T) {
	router := &Router{}
	request := OpenRequest{Node: "endpoint", Service: sessionmux.ServiceTCP}
	if _, err := router.Open(context.Background(), request); !errors.Is(err, ErrNoActiveSession) {
		t.Fatalf("empty router error=%v", err)
	}

	firstCleanup := router.Set("first", func(context.Context, OpenRequest) (io.ReadWriteCloser, error) {
		left, right := net.Pipe()
		_ = right.Close()
		return left, nil
	})
	if router.Binding() != "first" {
		t.Fatalf("binding=%q", router.Binding())
	}
	secondCalled := false
	secondCleanup := router.Set("second", func(context.Context, OpenRequest) (io.ReadWriteCloser, error) {
		secondCalled = true
		left, right := net.Pipe()
		_ = right.Close()
		return left, nil
	})
	firstCleanup()
	if router.Binding() != "second" {
		t.Fatalf("stale cleanup cleared binding=%q", router.Binding())
	}
	conn, err := router.Open(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if !secondCalled {
		t.Fatal("current opener was not called")
	}
	secondCleanup()
	if router.Binding() != "" {
		t.Fatalf("binding after cleanup=%q", router.Binding())
	}
	if _, err := router.Open(context.Background(), request); !errors.Is(err, ErrNoActiveSession) {
		t.Fatalf("cleared router error=%v", err)
	}
}
