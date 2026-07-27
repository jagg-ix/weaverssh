package instrument

import "testing"

func TestDefaultProbePointsAreStableAndTopicScoped(t *testing.T) {
	probes, err := DefaultProbePoints(ProviderEBPF, "wvtest")
	if err != nil {
		t.Fatal(err)
	}
	if len(probes) < 5 {
		t.Fatalf("probe count=%d, want at least 5", len(probes))
	}
	seen := map[string]bool{}
	for _, probe := range probes {
		if probe.ID == "" || probe.Component == "" || probe.EventType == "" || probe.Provider == "" {
			t.Fatalf("probe missing stable identity: %+v", probe)
		}
		if seen[probe.ID] {
			t.Fatalf("duplicate probe id %q", probe.ID)
		}
		seen[probe.ID] = true
		if probe.MQTTTopic == "" || probe.MQTTTopic[:len("wvtest/")] != "wvtest/" {
			t.Fatalf("probe topic not scoped to prefix: %+v", probe)
		}
	}
	if !seen["wv.instrument.ebpf.ssh.socket.connect"] {
		t.Fatal("missing ssh socket connect probe")
	}
	if !seen["wv.instrument.semantic.pubsub"] {
		t.Fatal("missing pubsub semantic correlation probe")
	}
}

func TestBuildPlanProfiles(t *testing.T) {
	minimal, err := BuildPlan(ProviderEBPF, "minimal", "weaverssh", []string{"origin", "node1", "node2"})
	if err != nil {
		t.Fatal(err)
	}
	if minimal.Provider != ProviderEBPF || minimal.PhysicalMode != PhysicalMode || len(minimal.Chain) != 3 {
		t.Fatalf("plan metadata wrong: %+v", minimal)
	}
	if len(minimal.ProbePoints) == 0 {
		t.Fatal("minimal plan should include default probes")
	}
	full, err := BuildPlan(ProviderEBPF, "full", "weaverssh", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(full.ProbePoints) <= len(minimal.ProbePoints) {
		t.Fatalf("full profile should include more probes than minimal: full=%d minimal=%d", len(full.ProbePoints), len(minimal.ProbePoints))
	}
	if _, err := BuildPlan(ProviderEBPF, "bad", "weaverssh", nil); err == nil {
		t.Fatal("expected invalid profile to fail")
	}
	if _, err := BuildPlan("dtrace", "minimal", "weaverssh", nil); err == nil {
		t.Fatal("expected unsupported provider to fail")
	}
}

func TestScriptRejectsInvalidProviderOrProfile(t *testing.T) {
	if _, err := Script(ProviderEBPF, "bad", "bpftrace"); err == nil {
		t.Fatal("expected invalid profile to fail")
	}
	if _, err := Script("dtrace", "minimal", "bpftrace"); err == nil {
		t.Fatal("expected invalid provider to fail")
	}
	script, err := Script(ProviderEBPF, "socket", "bpftrace")
	if err != nil {
		t.Fatal(err)
	}
	if script == "" || script[:len("#!/usr/bin/env bpftrace")] != "#!/usr/bin/env bpftrace" {
		t.Fatalf("unexpected script header: %q", script)
	}
}
