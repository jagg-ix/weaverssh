package sessionevents

import (
	"context"
	"errors"
	"testing"
)

type runtimeAuthorizerStub struct {
	calls int
	err   error
}

func (stub *runtimeAuthorizerStub) AuthorizeEvent(context.Context, OpenMetadata, Request) error {
	stub.calls++
	return stub.err
}

func TestRuntimeAuthorizationRunsAfterNativePolicy(t *testing.T) {
	engine, err := NewEngine(EngineConfig{
		Topology: []string{"source", "target"}, ChainSHA256: string(make([]byte, 64)), CurrentNode: "target",
		Policy: Policy{Version: PolicyVersion, Default: "deny", Rules: []Rule{{ID: "allow", Action: "allow", Sources: []string{"source"}, Operations: []string{OperationPublish}, Topics: []string{"allowed/#"}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	stub := &runtimeAuthorizerStub{err: ErrDenied}
	if err := SetRuntimeAuthorizer(engine, stub); err != nil {
		t.Fatal(err)
	}
	defer SetRuntimeAuthorizer(engine, nil)
	metadata := OpenMetadata{TargetNode: "target", SourceNode: "source", SourceBinding: "binding", ChainSHA256: string(make([]byte, 64))}
	err = engine.authorize(metadata, Request{Operation: OperationPublish, Topic: "allowed/topic", Payload: []byte("payload")})
	if !errors.Is(err, ErrDenied) || stub.calls != 1 {
		t.Fatalf("err=%v calls=%d", err, stub.calls)
	}
}

func TestNativeDenialSkipsRuntimeAuthorization(t *testing.T) {
	chain := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine, err := NewEngine(EngineConfig{
		Topology: []string{"source", "target"}, ChainSHA256: chain, CurrentNode: "target",
		Policy: Policy{Version: PolicyVersion, Default: "deny", Rules: []Rule{{ID: "allow", Action: "allow", Sources: []string{"source"}, Operations: []string{OperationPublish}, Topics: []string{"allowed/#"}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	stub := &runtimeAuthorizerStub{}
	_ = SetRuntimeAuthorizer(engine, stub)
	defer SetRuntimeAuthorizer(engine, nil)
	err = engine.authorize(OpenMetadata{TargetNode: "target", SourceNode: "source", SourceBinding: "binding", ChainSHA256: chain}, Request{Operation: OperationPublish, Topic: "blocked/topic", Payload: []byte("payload")})
	if !errors.Is(err, ErrDenied) || stub.calls != 0 {
		t.Fatalf("err=%v calls=%d", err, stub.calls)
	}
}
