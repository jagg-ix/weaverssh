package socketengine

import (
	"strings"
	"testing"
)

func TestInspectNormalizesMultipleListeners(t *testing.T) {
	config := Config{
		Version:        ConfigVersion,
		LoadBalance:    "least-connections",
		MaxConnections: 50,
		Routes: []Route{
			{Name: "registry", Listen: "tcp://localhost:5000", Node: "compute-node", Address: "registry.internal:5000", MaxConnections: 20},
			{Name: "database", Listen: "unix:///tmp/weaverssh-test-db.sock", Node: "compute-node", Network: "tcp4", Address: "127.0.0.1:5432", MaxConnections: 10},
		},
	}
	plan, err := Inspect(config)
	if err != nil {
		t.Fatal(err)
	}
	if plan.LoadBalance != "least-connections" || plan.MaxConnections != 50 || len(plan.Routes) != 2 {
		t.Fatalf("plan=%+v", plan)
	}
	if plan.QueueDepth != 32 || plan.ErrorQueueDepth != 128 || plan.ReadBufferBytes != 64<<10 {
		t.Fatalf("normalized bounds=%+v", plan)
	}
	if plan.DialTimeout != "30s" || plan.TCPKeepAlive != "30s" || plan.ShutdownTimeout != "10s" || plan.UnixMode != "0600" {
		t.Fatalf("normalized defaults=%+v", plan)
	}
	if plan.Routes[0].Listen != "tcp://127.0.0.1:5000" {
		t.Fatalf("TCP listener=%q", plan.Routes[0].Listen)
	}
	if plan.Routes[1].Listen != "unix:///tmp/weaverssh-test-db.sock" {
		t.Fatalf("Unix listener=%q", plan.Routes[1].Listen)
	}
}

func TestConfigRejectsDuplicateListener(t *testing.T) {
	_, err := Inspect(Config{Routes: []Route{
		{Name: "one", Listen: "tcp://127.0.0.1:5000", Node: "a", Address: "one.internal:443"},
		{Name: "two", Listen: "tcp4://127.0.0.1:5000", Node: "b", Address: "two.internal:443"},
	}})
	if err == nil || !strings.Contains(err.Error(), "duplicate listener") {
		t.Fatalf("error=%v", err)
	}
}

func TestConfigRejectsNonLoopbackByDefault(t *testing.T) {
	_, err := Inspect(Config{Routes: []Route{{Name: "public", Listen: "tcp://0.0.0.0:5000", Node: "node", Address: "service.internal:443"}}})
	if err == nil || !strings.Contains(err.Error(), "allow_non_loopback") {
		t.Fatalf("error=%v", err)
	}
	if _, err := Inspect(Config{AllowNonLoopback: true, Routes: []Route{{Name: "public", Listen: "tcp://0.0.0.0:5000", Node: "node", Address: "service.internal:443"}}}); err != nil {
		t.Fatal(err)
	}
}

func TestConfigRejectsEphemeralAndRelativeUnixListeners(t *testing.T) {
	for _, listener := range []string{"tcp://127.0.0.1:0", "unix://relative.sock"} {
		_, err := Inspect(Config{Routes: []Route{{Name: "route", Listen: listener, Node: "node", Address: "service.internal:443"}}})
		if err == nil {
			t.Fatalf("listener %q was accepted", listener)
		}
	}
}

func TestLoadConfigRejectsTrailingAndUnknownJSON(t *testing.T) {
	for _, payload := range []string{
		`{"version":"weaverssh.socket-engine.v1","routes":[{"name":"a","listen":"tcp://127.0.0.1:5000","node":"n","address":"h:1"}]} {}`,
		`{"version":"weaverssh.socket-engine.v1","client_write_queue":16,"routes":[{"name":"a","listen":"tcp://127.0.0.1:5000","node":"n","address":"h:1"}]}`,
	} {
		_, err := LoadConfig(strings.NewReader(payload))
		if err == nil {
			t.Fatalf("payload was accepted: %s", payload)
		}
	}
}

func TestConfigRejectsPerRouteLimitAboveGlobalLimit(t *testing.T) {
	_, err := Inspect(Config{MaxConnections: 4, Routes: []Route{{Name: "route", Listen: "tcp://127.0.0.1:5000", Node: "node", Address: "service.internal:443", MaxConnections: 5}}})
	if err == nil || !strings.Contains(err.Error(), "exceeds global limit") {
		t.Fatalf("error=%v", err)
	}
}

func TestConfigRejectsUnboundedRuntimeSettings(t *testing.T) {
	base := []Route{{Name: "route", Listen: "tcp://127.0.0.1:5000", Node: "node", Address: "service.internal:443"}}
	for _, config := range []Config{
		{Routes: base, EventLoops: maximumEventLoops + 1},
		{Routes: base, QueueDepth: maximumQueueDepth + 1},
		{Routes: base, ErrorQueueDepth: maximumQueueDepth + 1},
		{Routes: base, DialTimeout: "0s"},
		{Routes: base, ShutdownTimeout: "0s"},
	} {
		if _, err := Inspect(config); err == nil {
			t.Fatalf("config was accepted: %+v", config)
		}
	}
}
