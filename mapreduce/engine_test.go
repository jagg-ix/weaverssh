package mapreduce

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func testPolicy(t *testing.T) *Policy {
	t.Helper()
	policy, err := NewPolicy(Policy{
		Version: PolicyVersion,
		Default: EffectDeny,
		Rules: []Rule{{
			Name:        "allow-chain-compute",
			Effect:      EffectAllow,
			SourceNodes: []string{"*"},
			SourceRoles: []string{"origin", "intermediate", "endpoint", "single"},
			TargetNodes: []string{"*"},
			Plugins:     []string{"word-count", "hook-map", "system.describe"},
			Operations:  []Operation{OperationDescribe, OperationMap, OperationReduce, OperationRun},
			Limits: Limits{
				MaxItems: 64, MaxInputBytes: 1 << 20,
				MaxOutputRecords: 128, MaxOutputBytes: 1 << 20,
				MaxParallel: 4, MaxFanout: 8,
				MaxDurationMillis: 5000, MaxValuesPerKey: 64,
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func testEngine(t *testing.T) *Engine {
	t.Helper()
	registry := NewRegistry()
	err := registry.RegisterPlugin(Plugin{
		Descriptor: Descriptor{Name: "word-count", Version: "1"},
		Map: func(_ context.Context, input MapInput) ([]Record, error) {
			words := strings.Fields(string(input.Record.Value))
			out := make([]Record, 0, len(words))
			for _, word := range words {
				out = append(out, Record{Key: word, Value: []byte("1")})
			}
			return out, nil
		},
		Reduce: func(_ context.Context, input ReduceInput) (Record, error) {
			total := 0
			for _, value := range input.Group.Values {
				n, err := strconv.Atoi(string(value))
				if err != nil {
					return Record{}, err
				}
				total += n
			}
			return Record{Key: input.Group.Key, Value: []byte(strconv.Itoa(total))}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(EngineConfig{
		Topology: Topology{
			ChainSHA256: strings.Repeat("a", 64),
			Nodes:       []string{"origin", "jump", "endpoint"},
			CurrentNode: "endpoint",
		},
		Registry: registry,
		Policy:   testPolicy(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func TestEngineRunFromIntermediateEndpoint(t *testing.T) {
	engine := testEngine(t)
	response, err := engine.Execute(context.Background(), OpenMetadata{
		Protocol: OpenProtocolVersion, SourceNode: "jump", SourceBinding: "binding",
		ChainSHA256: strings.Repeat("a", 64), TargetNode: "endpoint",
	}, Request{
		Protocol: ProtocolVersion, ID: "job-1", Operation: OperationRun,
		Plugin: "word-count",
		Records: []Record{{Value: []byte("red blue red")}, {Value: []byte("blue green")}},
		RequestedParallel: 2, Fanout: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, record := range response.Records {
		got[record.Key] = string(record.Value)
	}
	want := map[string]string{"blue": "2", "green": "1", "red": "2"}
	if !mapsEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
	if !response.Decision.Allowed || response.Decision.PolicySHA256 == "" {
		t.Fatalf("decision=%+v", response.Decision)
	}
}

func TestPolicyDenyOverridesAllow(t *testing.T) {
	policy, err := NewPolicy(Policy{Version: PolicyVersion, Default: EffectDeny, Rules: []Rule{
		{Name: "allow", Effect: EffectAllow, SourceNodes: []string{"*"}, TargetNodes: []string{"*"}, Plugins: []string{"word-count"}, Operations: []Operation{OperationRun}},
		{Name: "deny-jump", Effect: EffectDeny, SourceNodes: []string{"jump"}, TargetNodes: []string{"*"}, Plugins: []string{"word-count"}, Operations: []Operation{OperationRun}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = policy.Evaluate(Invocation{
		SourceNode: "jump", TargetNode: "endpoint", SourceRole: "intermediate",
		Operation: OperationRun, Plugin: "word-count", Items: 1,
	})
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("err=%v", err)
	}
}

func TestMapHookCanImplementMissingMapStage(t *testing.T) {
	registry := NewRegistry()
	if err := registry.RegisterPlugin(Plugin{
		Descriptor: Descriptor{Name: "hook-map", Version: "1"},
		Reduce: func(_ context.Context, input ReduceInput) (Record, error) {
			return Record{Key: input.Group.Key, Value: []byte("ok")}, nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := registry.RegisterMapHook("hook-map", 0, func(_ context.Context, input MapInput, _ MapFunc) ([]Record, error) {
		return []Record{{Key: "hooked", Value: append([]byte(nil), input.Record.Value...)}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	out, err := registry.Map(context.Background(), "hook-map", MapInput{Record: Record{Value: []byte("value")}})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Key != "hooked" || string(out[0].Value) != "value" {
		t.Fatalf("out=%v", out)
	}
}

func TestWireRoundTripAndBrokerBinding(t *testing.T) {
	engine := testEngine(t)
	raw, err := NewOpenMetadata("endpoint")
	if err != nil {
		t.Fatal(err)
	}
	bound, err := BindSource(raw, "jump", "binding", strings.Repeat("a", 64), "endpoint")
	if err != nil {
		t.Fatal(err)
	}
	server, client := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- engine.Serve(context.Background(), server, bound) }()
	response, err := CallStream(context.Background(), client, Request{
		Protocol: ProtocolVersion, ID: "job-2", Operation: OperationMap,
		Plugin: "word-count", Records: []Record{{Value: []byte("x y")}}, Fanout: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Records) != 2 {
		t.Fatalf("records=%v", response.Records)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPolicyDigestStableAcrossEquivalentInput(t *testing.T) {
	p1 := testPolicy(t)
	raw, err := json.Marshal(Policy{Version: PolicyVersion, Default: EffectDeny, Rules: []Rule{{
		Name: "allow-chain-compute", Effect: EffectAllow,
		SourceNodes: []string{"*"},
		SourceRoles: []string{"single", "endpoint", "intermediate", "origin"},
		TargetNodes: []string{"*"},
		Plugins:     []string{"system.describe", "hook-map", "word-count"},
		Operations:  []Operation{OperationRun, OperationReduce, OperationMap, OperationDescribe},
		Limits: Limits{
			MaxItems: 64, MaxInputBytes: 1 << 20,
			MaxOutputRecords: 128, MaxOutputBytes: 1 << 20,
			MaxParallel: 4, MaxFanout: 8,
			MaxDurationMillis: 5000, MaxValuesPerKey: 64,
		},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	p2, err := ParsePolicy(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p1.SHA256() != p2.SHA256() {
		t.Fatalf("digest mismatch %s %s", p1.SHA256(), p2.SHA256())
	}
}

func TestOutputLimit(t *testing.T) {
	policy, err := NewPolicy(Policy{Version: PolicyVersion, Default: EffectDeny, Rules: []Rule{{
		Name: "tiny", Effect: EffectAllow, SourceNodes: []string{"*"}, TargetNodes: []string{"*"},
		Plugins: []string{"word-count"}, Operations: []Operation{OperationMap},
		Limits: Limits{MaxItems: 10, MaxInputBytes: 1000, MaxOutputRecords: 1, MaxOutputBytes: 1000, MaxParallel: 1, MaxFanout: 1, MaxDurationMillis: 1000, MaxValuesPerKey: 10},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	registry := NewRegistry()
	if err := registry.RegisterPlugin(Plugin{
		Descriptor: Descriptor{Name: "word-count", Version: "1"},
		Map: func(context.Context, MapInput) ([]Record, error) {
			return []Record{{Key: "a"}, {Key: "b"}}, nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(EngineConfig{
		Topology: Topology{ChainSHA256: strings.Repeat("a", 64), Nodes: []string{"n"}, CurrentNode: "n"},
		Registry: registry, Policy: policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = engine.Execute(context.Background(), OpenMetadata{
		Protocol: OpenProtocolVersion, SourceNode: "n", SourceBinding: "b",
		ChainSHA256: strings.Repeat("a", 64), TargetNode: "n",
	}, Request{
		Protocol: ProtocolVersion, ID: "j", Operation: OperationMap,
		Plugin: "word-count", Records: []Record{{Value: []byte("x")}}, Fanout: 1,
	})
	if !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("err=%v", err)
	}
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if b[key] != value {
			return false
		}
	}
	return true
}

func TestFrameRejectsOversize(t *testing.T) {
	var buf bytes.Buffer
	if err := writeFrame(&buf, make([]byte, MaxMessageBytes+1)); err == nil {
		t.Fatal("expected error")
	}
}

type fakeCoordinatorCaller struct {
	mu    sync.Mutex
	calls []string
}

func (f *fakeCoordinatorCaller) Call(_ context.Context, target string, request Request) (Response, error) {
	f.mu.Lock()
	f.calls = append(f.calls, target+":"+string(request.Operation))
	f.mu.Unlock()
	switch request.Operation {
	case OperationMap:
		out := make([]Record, 0, len(request.Records))
		for _, record := range request.Records {
			out = append(out, Record{Key: string(record.Value), Value: []byte("1")})
		}
		return Response{Protocol: ProtocolVersion, ID: request.ID, Records: out}, nil
	case OperationReduce:
		out := make([]Record, 0, len(request.Groups))
		for _, group := range request.Groups {
			out = append(out, Record{Key: group.Key, Value: []byte(strconv.Itoa(len(group.Values)))})
		}
		return Response{Protocol: ProtocolVersion, ID: request.ID, Records: out}, nil
	default:
		return Response{}, ErrInvalidRequest
	}
}

func TestCoordinatorCallsAnyEndpointsAndReduces(t *testing.T) {
	caller := &fakeCoordinatorCaller{}
	coordinator := Coordinator{Caller: caller}
	out, err := coordinator.Run(context.Background(), JobSpec{
		Plugin: "word-count",
		Records: []Record{{Value: []byte("red")}, {Value: []byte("blue")}, {Value: []byte("red")}},
		MapTargets: []string{"jump", "endpoint"}, ReduceTarget: "origin",
	})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, record := range out {
		got[record.Key] = string(record.Value)
	}
	if !mapsEqual(got, map[string]string{"blue": "1", "red": "2"}) {
		t.Fatalf("out=%v", out)
	}
	caller.mu.Lock()
	calls := append([]string(nil), caller.calls...)
	caller.mu.Unlock()
	sort.Strings(calls)
	want := []string{"endpoint:map", "jump:map", "origin:reduce"}
	if strings.Join(calls, ",") != strings.Join(want, ",") {
		t.Fatalf("calls=%v want=%v", calls, want)
	}
}

func TestParsePolicyRejectsTrailingData(t *testing.T) {
	_, err := ParsePolicy([]byte(`{"version":"weaverssh.mapreduce-policy.v1","default":"deny","rules":[]} trailing`))
	if err == nil {
		t.Fatal("expected trailing policy data rejection")
	}
}

func TestBindSourcePreservesRoutedOrigin(t *testing.T) {
	initial, err := NewOpenMetadata("endpoint")
	if err != nil {
		t.Fatal(err)
	}
	bound, err := BindSource(initial, "origin", "binding-origin", strings.Repeat("a", 64), "endpoint")
	if err != nil {
		t.Fatal(err)
	}
	forwarded, err := BindSource(bound, "jump", "binding-jump", strings.Repeat("a", 64), "endpoint")
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := ParseOpenMetadata(forwarded)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.SourceNode != "origin" || metadata.SourceBinding != "binding-origin" {
		t.Fatalf("metadata=%+v", metadata)
	}
}

func TestBindSourceRejectsForwardedChainMismatch(t *testing.T) {
	initial, err := NewOpenMetadata("endpoint")
	if err != nil {
		t.Fatal(err)
	}
	bound, err := BindSource(initial, "origin", "binding-origin", strings.Repeat("a", 64), "endpoint")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BindSource(bound, "jump", "binding-jump", strings.Repeat("b", 64), "endpoint"); err == nil {
		t.Fatal("expected chain mismatch rejection")
	}
}
