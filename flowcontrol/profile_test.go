package flowcontrol

import "testing"

func TestBuiltinProfilesAreMatched(t *testing.T) {
	for _, name := range Names() {
		p, err := Builtin(name)
		if err != nil {
			t.Fatalf("Builtin(%q): %v", name, err)
		}
		if reasons := p.Validate(); len(reasons) != 0 {
			t.Fatalf("profile %s mismatch: %v", name, reasons)
		}
		if p.RelayReadBytes != p.WebSocketFrameBytes {
			t.Fatalf("profile %s relay=%d frame=%d", name, p.RelayReadBytes, p.WebSocketFrameBytes)
		}
	}
}

func TestBuildPlanComputesBDPAndWarnings(t *testing.T) {
	plan, err := BuildPlan(ProfileRealtime, 1000, 10000000) // 10 ms
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if plan.Version != ContractVersion || !plan.Matched {
		t.Fatalf("unexpected plan: %+v", plan)
	}
	if plan.BDPBytes <= 0 || plan.RecommendedQueueDepth <= 0 {
		t.Fatalf("missing BDP guidance: %+v", plan)
	}
	if len(plan.BenchmarkPayloadBytes) != 3 {
		t.Fatalf("benchmark payloads=%v", plan.BenchmarkPayloadBytes)
	}
}

func TestValidateRejectsDriftBetweenRelayAndWebSocket(t *testing.T) {
	p, err := Builtin(ProfileBalanced)
	if err != nil {
		t.Fatal(err)
	}
	p.RelayReadBytes = p.WebSocketFrameBytes / 2
	reasons := p.Validate()
	if len(reasons) == 0 {
		t.Fatal("expected mismatch")
	}
	want := "relay read chunk must match websocket frame payload"
	for _, got := range reasons {
		if got == want {
			return
		}
	}
	t.Fatalf("missing reason %q in %v", want, reasons)
}
