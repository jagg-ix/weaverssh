package flowcontrol

import (
	"testing"
	"time"
)

func TestOptimizeLatencyPolicySelectsRealtimeForSmallPayload(t *testing.T) {
	decision, err := Optimize(OptimizationRequest{
		Policy:        PolicyLatency,
		PayloadBytes:  512,
		BandwidthMbps: 100,
		RTT:           20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Optimize: %v", err)
	}
	if decision.Selected.SelectedDataProfile != DataProfileRealtime {
		t.Fatalf("selected data profile=%s want realtime", decision.Selected.SelectedDataProfile)
	}
	if decision.Selected.TransportMode != TransportDual {
		t.Fatalf("transport mode=%s want dual", decision.Selected.TransportMode)
	}
}

func TestOptimizeThroughputPolicySelectsBulkForLargePayload(t *testing.T) {
	decision, err := Optimize(OptimizationRequest{
		Policy:        PolicyThroughput,
		PayloadBytes:  8 * 1024 * 1024,
		BandwidthMbps: 1000,
		RTT:           25 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Optimize: %v", err)
	}
	if decision.Selected.SelectedDataProfile != DataProfileBulk {
		t.Fatalf("selected data profile=%s want bulk", decision.Selected.SelectedDataProfile)
	}
	if decision.Selected.EstimatedThroughputMbps <= 0 {
		t.Fatalf("throughput not estimated: %+v", decision.Selected)
	}
}

func TestOptimizeRejectsPolicyViolations(t *testing.T) {
	_, err := Optimize(OptimizationRequest{
		Policy:         PolicyThroughput,
		PayloadBytes:   8 * 1024 * 1024,
		BandwidthMbps:  10,
		RTT:            100 * time.Millisecond,
		MaxMemoryBytes: 1024,
	})
	if err == nil {
		t.Fatal("expected no candidate due memory constraint")
	}
}
