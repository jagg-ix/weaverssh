package pubsub

import (
	"context"
	"errors"
	"testing"
)

func TestEnvironmentEventContractCoversRequestedScopes(t *testing.T) {
	cases := []EnvironmentScope{
		EnvironmentScopeSystemChain,
		EnvironmentScopeHost,
		EnvironmentScopeConnection,
		EnvironmentScopeQoS,
		EnvironmentScopeFilesystem,
		EnvironmentScopeFile,
		EnvironmentScopeData,
	}
	for _, scope := range cases {
		event := NewEnvironmentEvent(scope, "status", EnvironmentEvent{
			ChainID:       "prod-chain",
			NodeID:        "node-a",
			HostID:        "host-a",
			ConnectionID:  "conn-a",
			QoSClass:      "bulk",
			FilesystemID:  "vfs-root",
			Path:          "/srv/data/file.txt",
			DataClass:     "artifact",
			Protocol:      "ssh-x11-websocket",
			Direction:     "ingress",
			Status:        "ready",
			Bytes:         1024,
			LatencyMillis: 12,
		})
		if err := event.Validate(); err != nil {
			t.Fatalf("%s event validate: %v", scope, err)
		}
		if event.Component != ComponentEnvironment || event.Origin != EventOriginExternal {
			t.Fatalf("%s event component/origin mismatch: %+v", scope, event)
		}
		checks := map[string]string{
			"kind":          EnvironmentEventKind,
			"scope":         string(scope),
			"operation":     "status",
			"chain_id":      "prod-chain",
			"node_id":       "node-a",
			"host_id":       "host-a",
			"connection_id": "conn-a",
			"qos_class":     "bulk",
			"filesystem_id": "vfs-root",
			"path":          "/srv/data/file.txt",
			"data_class":    "artifact",
			"protocol":      "ssh-x11-websocket",
			"direction":     "ingress",
			"status":        "ready",
			"bytes":         "1024",
			"latency_ms":    "12",
		}
		for key, want := range checks {
			if got := event.Fields[key]; got != want {
				t.Fatalf("%s field %s=%q want %q fields=%+v", scope, key, got, want, event.Fields)
			}
		}
	}
}

func TestEnvironmentScopeAliases(t *testing.T) {
	checks := map[string]EnvironmentScope{
		"system-chain":       EnvironmentScopeSystemChain,
		"chain":              EnvironmentScopeSystemChain,
		"node":               EnvironmentScopeHost,
		"conn":               EnvironmentScopeConnection,
		"quos":               EnvironmentScopeQoS,
		"quality-of-service": EnvironmentScopeQoS,
		"fs":                 EnvironmentScopeFilesystem,
		"payload":            EnvironmentScopeData,
	}
	for raw, want := range checks {
		got, err := ParseEnvironmentScope(raw)
		if err != nil || got != want {
			t.Fatalf("ParseEnvironmentScope(%q)=(%q,%v), want %q", raw, got, err, want)
		}
	}
}

func TestEnvironmentHooksCanGateExternalHostEvents(t *testing.T) {
	api := NewAPI(APIConfig{})
	if err := api.RegisterHook(Hook{
		ID:       "deny-host-quarantine",
		PluginID: "policy",
		Point:    HookBeforeEnvironmentEvent,
		Filter: HookFilter{
			Origins:    []EventOrigin{EventOriginExternal},
			Components: []string{ComponentEnvironment},
			Fields:     map[string]string{"scope": string(EnvironmentScopeHost), "status": "quarantine"},
		},
		Handler: func(context.Context, HookInvocation) (HookDecision, error) {
			return HookDecision{Action: HookDrop, Reason: "host quarantined"}, nil
		},
	}); err != nil {
		t.Fatalf("RegisterHook: %v", err)
	}
	dispatch, err := api.BeforeEnvironmentEvent(context.Background(), EnvironmentScopeHost, "status", EnvironmentEvent{HostID: "linode-a", Status: "quarantine"})
	if err != nil {
		t.Fatalf("BeforeEnvironmentEvent: %v", err)
	}
	if !dispatch.Dropped || dispatch.Matched != 1 || dispatch.Results[0].Reason != "host quarantined" {
		t.Fatalf("unexpected host dispatch: %+v", dispatch)
	}
	dispatch, err = api.BeforeEnvironmentEvent(context.Background(), EnvironmentScopeConnection, "status", EnvironmentEvent{ConnectionID: "conn-a", Status: "quarantine"})
	if err != nil {
		t.Fatalf("BeforeEnvironmentEvent connection: %v", err)
	}
	if dispatch.Dropped || dispatch.Matched != 0 {
		t.Fatalf("connection event should not match host hook: %+v", dispatch)
	}
}

func TestEnvironmentPluginRegistersScopedHooks(t *testing.T) {
	var called int
	plugin, err := NewEnvironmentPlugin(EnvironmentPluginConfig{
		ID:     "external-env",
		Scopes: []EnvironmentScope{EnvironmentScopeQoS, EnvironmentScopeData},
		Points: []HookPoint{HookOnEnvironmentEvent},
		Handler: func(context.Context, HookInvocation) (HookDecision, error) {
			called++
			return HookDecision{Action: HookContinue, Reason: "observed"}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewEnvironmentPlugin: %v", err)
	}
	api := NewAPI(APIConfig{})
	if err := api.RegisterPlugin(plugin); err != nil {
		t.Fatalf("RegisterPlugin: %v", err)
	}
	qos, err := api.ObserveEnvironmentEvent(context.Background(), "quos", "pressure", EnvironmentEvent{QoSClass: "realtime", LatencyMillis: 95})
	if err != nil {
		t.Fatalf("ObserveEnvironmentEvent qos: %v", err)
	}
	if qos.Matched != 1 || called != 1 {
		t.Fatalf("qos dispatch mismatch: %+v called=%d", qos, called)
	}
	host, err := api.ObserveEnvironmentEvent(context.Background(), EnvironmentScopeHost, "status", EnvironmentEvent{HostID: "host-a"})
	if err != nil {
		t.Fatalf("ObserveEnvironmentEvent host: %v", err)
	}
	if host.Matched != 0 || called != 1 {
		t.Fatalf("host event should not match scoped plugin: %+v called=%d", host, called)
	}
}

func TestRunEnvironmentOperationReturnsDropError(t *testing.T) {
	api := NewAPI(APIConfig{})
	if err := api.RegisterHook(Hook{
		ID:       "drop-data-egress",
		PluginID: "policy",
		Point:    HookBeforeEnvironmentEvent,
		Filter: HookFilter{
			Components: []string{ComponentEnvironment},
			Fields:     map[string]string{"scope": string(EnvironmentScopeData), "direction": "egress"},
		},
		Handler: func(context.Context, HookInvocation) (HookDecision, error) {
			return HookDecision{Action: HookDrop, Reason: "egress disabled"}, nil
		},
	}); err != nil {
		t.Fatalf("RegisterHook: %v", err)
	}
	_, err := api.RunEnvironmentOperation(context.Background(), EnvironmentScopeData, "send", EnvironmentEvent{Direction: "egress", DataClass: "artifact"}, func(context.Context) error { return nil })
	if !errors.Is(err, ErrEventDropped) {
		t.Fatalf("RunEnvironmentOperation error=%v want ErrEventDropped", err)
	}
}
