package flowcontrol

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

const (
	PolicyLatency     = "latency"
	PolicyThroughput  = "throughput"
	PolicyBalanced    = "balanced"
	PolicyReliability = "reliability"

	TransportSingle = "single"
	TransportDual   = "dual"

	RouteAuto     = "auto"
	RouteRealtime = "realtime"
	RouteBulk     = "bulk"

	DataProfileRealtime = "realtime"
	DataProfileBulk     = "bulk"
)

// OptimizationRequest describes the targeted policy and path measurements used
// to calculate a runtime configuration. Values are intentionally simple so this
// can be fed from benchmarks, MCP agents, Jepsen runs, or operator scripts.
type OptimizationRequest struct {
	Policy            string        `json:"policy"`
	PayloadBytes      int           `json:"payload_bytes"`
	BandwidthMbps     float64       `json:"bandwidth_mbps"`
	RTT               time.Duration `json:"rtt_ns"`
	HopCount          int           `json:"hop_count"`
	LossPercent       float64       `json:"loss_percent"`
	ConcurrentStreams int           `json:"concurrent_streams"`
	MaxMemoryBytes    int64         `json:"max_memory_bytes,omitempty"`
	MinThroughputMbps float64       `json:"min_throughput_mbps,omitempty"`
	MaxLatencyMillis  float64       `json:"max_latency_ms,omitempty"`
	AllowRealtime     bool          `json:"allow_realtime"`
	AllowBulk         bool          `json:"allow_bulk"`
}

type OptimizationDecision struct {
	Version      string              `json:"version"`
	Algorithm    string              `json:"algorithm"`
	Policy       string              `json:"policy"`
	Selected     CandidateConfig     `json:"selected"`
	Alternatives []CandidateConfig   `json:"alternatives"`
	Warnings     []string            `json:"warnings,omitempty"`
	Commands     []string            `json:"commands"`
	Request      OptimizationRequest `json:"request"`
}

type CandidateConfig struct {
	FlowProfile             string   `json:"flow_profile"`
	TransportMode           string   `json:"transport_mode"`
	RoutePolicy             string   `json:"route_policy"`
	SelectedDataProfile     string   `json:"selected_data_profile"`
	RealtimeThresholdBytes  int      `json:"realtime_threshold_bytes"`
	Score                   float64  `json:"score"`
	EstimatedLatencyMillis  float64  `json:"estimated_latency_ms"`
	EstimatedThroughputMbps float64  `json:"estimated_throughput_mbps"`
	EstimatedReliability    float64  `json:"estimated_reliability"`
	EstimatedMemoryBytes    int64    `json:"estimated_memory_bytes"`
	InFlightCapacityBytes   int64    `json:"in_flight_capacity_bytes"`
	RecommendedQueueDepth   int      `json:"recommended_queue_depth"`
	Rejected                bool     `json:"rejected"`
	Reasons                 []string `json:"reasons,omitempty"`
}

type objectiveWeights struct {
	latency     float64
	throughput  float64
	reliability float64
	memory      float64
}

// Optimize calculates the best configuration for the requested policy using a
// weighted multi-objective route score over valid runtime profiles.
func Optimize(req OptimizationRequest) (OptimizationDecision, error) {
	req = normalizeOptimizationRequest(req)
	weights, err := weightsForPolicy(req.Policy)
	if err != nil {
		return OptimizationDecision{}, err
	}
	candidates, warnings := buildCandidates(req, weights)
	if len(candidates) == 0 {
		return OptimizationDecision{}, fmt.Errorf("no routing candidates generated")
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Rejected != candidates[j].Rejected {
			return !candidates[i].Rejected
		}
		if candidates[i].Score == candidates[j].Score {
			return candidates[i].FlowProfile < candidates[j].FlowProfile
		}
		return candidates[i].Score < candidates[j].Score
	})
	selected := candidates[0]
	if selected.Rejected {
		return OptimizationDecision{}, fmt.Errorf("no candidate satisfies targeted policy constraints")
	}
	decision := OptimizationDecision{
		Version:      ContractVersion,
		Algorithm:    "weighted_multi_objective_candidate_routing_v1",
		Policy:       req.Policy,
		Selected:     selected,
		Alternatives: candidates,
		Warnings:     warnings,
		Request:      req,
	}
	decision.Commands = []string{
		fmt.Sprintf("wv flow plan --profile %s --bandwidth-mbps %.0f --rtt %s", selected.FlowProfile, req.BandwidthMbps, req.RTT),
		fmt.Sprintf("wv flow validate --profile %s", selected.FlowProfile),
		fmt.Sprintf("wv flow optimize --policy %s --payload-bytes %d --bandwidth-mbps %.0f --rtt %s", req.Policy, req.PayloadBytes, req.BandwidthMbps, req.RTT),
	}
	return decision, nil
}

func normalizeOptimizationRequest(req OptimizationRequest) OptimizationRequest {
	req.Policy = strings.ToLower(strings.TrimSpace(req.Policy))
	if req.Policy == "" || req.Policy == "default" {
		req.Policy = PolicyBalanced
	}
	if req.PayloadBytes <= 0 {
		req.PayloadBytes = 4096
	}
	if req.BandwidthMbps <= 0 {
		req.BandwidthMbps = 100
	}
	if req.RTT <= 0 {
		req.RTT = DefaultRTT
	}
	if req.HopCount <= 0 {
		req.HopCount = 1
	}
	if req.LossPercent < 0 {
		req.LossPercent = 0
	}
	if req.ConcurrentStreams <= 0 {
		req.ConcurrentStreams = 1
	}
	if req.MaxMemoryBytes <= 0 {
		req.MaxMemoryBytes = 4 * 1024 * 1024
	}
	// Keep backward compatibility with zero-value structs: both are allowed unless
	// the CLI or caller explicitly disables one and leaves the other enabled.
	if !req.AllowRealtime && !req.AllowBulk {
		req.AllowRealtime = true
		req.AllowBulk = true
	}
	return req
}

func weightsForPolicy(policy string) (objectiveWeights, error) {
	switch policy {
	case PolicyLatency:
		return objectiveWeights{latency: 0.60, throughput: 0.15, reliability: 0.15, memory: 0.10}, nil
	case PolicyThroughput:
		return objectiveWeights{latency: 0.15, throughput: 0.60, reliability: 0.15, memory: 0.10}, nil
	case PolicyReliability:
		return objectiveWeights{latency: 0.20, throughput: 0.20, reliability: 0.45, memory: 0.15}, nil
	case PolicyBalanced:
		return objectiveWeights{latency: 0.30, throughput: 0.30, reliability: 0.25, memory: 0.15}, nil
	default:
		return objectiveWeights{}, fmt.Errorf("unsupported targeted policy %q", policy)
	}
}

func buildCandidates(req OptimizationRequest, weights objectiveWeights) ([]CandidateConfig, []string) {
	var candidates []CandidateConfig
	var warnings []string
	modes := []string{TransportDual, TransportSingle}
	routes := []string{RouteAuto, RouteRealtime, RouteBulk}
	for _, profileName := range Names() {
		profile, err := Builtin(profileName)
		if err != nil {
			continue
		}
		plan, _ := BuildPlan(profileName, req.BandwidthMbps, req.RTT)
		threshold := thresholdForPolicy(req.Policy, profile)
		for _, mode := range modes {
			for _, routePolicy := range routes {
				if mode == TransportSingle && routePolicy == RouteRealtime {
					continue
				}
				selected := selectDataProfile(mode, routePolicy, req.PayloadBytes, threshold)
				candidate := estimateCandidate(req, weights, profile, plan, mode, routePolicy, selected, threshold)
				candidates = append(candidates, candidate)
			}
		}
	}
	if req.MaxLatencyMillis == 0 {
		warnings = append(warnings, "no explicit max latency constraint; using weighted score only")
	}
	if req.MinThroughputMbps == 0 {
		warnings = append(warnings, "no explicit min throughput constraint; using weighted score only")
	}
	return candidates, warnings
}

func thresholdForPolicy(policy string, p Profile) int {
	switch policy {
	case PolicyLatency:
		return maxInt(1, p.WebSocketFrameBytes*2)
	case PolicyThroughput:
		return maxInt(1, p.WebSocketFrameBytes/2)
	case PolicyReliability:
		return p.WebSocketFrameBytes
	default:
		return p.WebSocketFrameBytes
	}
}

func selectDataProfile(mode string, routePolicy string, payloadBytes int, threshold int) string {
	if mode == TransportSingle {
		return DataProfileBulk
	}
	switch routePolicy {
	case RouteRealtime:
		return DataProfileRealtime
	case RouteBulk:
		return DataProfileBulk
	default:
		if payloadBytes <= threshold {
			return DataProfileRealtime
		}
		return DataProfileBulk
	}
}

func estimateCandidate(req OptimizationRequest, weights objectiveWeights, profile Profile, plan Plan, mode, routePolicy, selected string, threshold int) CandidateConfig {
	profile = profile.Normalized()
	capacity := float64(plan.InFlightCapacityBytes)
	if capacity <= 0 {
		capacity = float64(profile.WebSocketFrameBytes * profile.QueueDepth)
	}
	rttMs := float64(req.RTT) / float64(time.Millisecond)
	payloadSerializationMs := (float64(req.PayloadBytes) * 8 / (req.BandwidthMbps * 1000 * 1000)) * 1000
	capacityMbps := (capacity * 8 / req.RTT.Seconds()) / 1000 / 1000
	estimatedThroughput := math.Min(req.BandwidthMbps, capacityMbps)
	if selected == DataProfileRealtime {
		estimatedThroughput *= 0.85
	} else if !profile.TCPNoDelay {
		estimatedThroughput *= 0.98
	}
	if estimatedThroughput < 0 {
		estimatedThroughput = 0
	}

	queuePenaltyMs := 0.0
	if selected == DataProfileBulk {
		queuePenaltyMs = math.Min(rttMs*0.35, float64(plan.EstimatedDrainTimeMillis)+rttMs*0.10)
	}
	if !profile.TCPNoDelay {
		queuePenaltyMs += math.Min(2.0, rttMs*0.05)
	}
	latencyMs := rttMs + payloadSerializationMs + queuePenaltyMs + float64(req.HopCount-1)*0.75 + req.LossPercent*rttMs*0.02

	reliability := 1.0 - (req.LossPercent / 100.0) - float64(req.HopCount-1)*0.01
	if selected == DataProfileRealtime && profile.QueueDepth < plan.RecommendedQueueDepth {
		reliability -= 0.03
	}
	if routePolicy != RouteAuto {
		reliability -= 0.01
	}
	if reliability < 0 {
		reliability = 0
	}
	if reliability > 1 {
		reliability = 1
	}

	memory := int64(profile.SSHSocketBufferBytes+profile.WebSocketReadBufferBytes+profile.WebSocketWriteBufferBytes) + int64(profile.WebSocketFrameBytes*profile.QueueDepth*req.ConcurrentStreams)

	latencyTarget := req.MaxLatencyMillis
	if latencyTarget <= 0 {
		latencyTarget = math.Max(rttMs*2.0, 1.0)
	}
	latencyCost := clamp01(latencyMs / latencyTarget)
	throughputTarget := req.MinThroughputMbps
	if throughputTarget <= 0 {
		throughputTarget = req.BandwidthMbps
	}
	throughputCost := clamp01(1 - estimatedThroughput/throughputTarget)
	reliabilityCost := clamp01(1 - reliability)
	memoryCost := clamp01(float64(memory) / float64(req.MaxMemoryBytes))
	score := weights.latency*latencyCost + weights.throughput*throughputCost + weights.reliability*reliabilityCost + weights.memory*memoryCost

	candidate := CandidateConfig{
		FlowProfile:             profile.Name,
		TransportMode:           mode,
		RoutePolicy:             routePolicy,
		SelectedDataProfile:     selected,
		RealtimeThresholdBytes:  threshold,
		Score:                   math.Round(score*10000) / 10000,
		EstimatedLatencyMillis:  math.Round(latencyMs*100) / 100,
		EstimatedThroughputMbps: math.Round(estimatedThroughput*100) / 100,
		EstimatedReliability:    math.Round(reliability*10000) / 10000,
		EstimatedMemoryBytes:    memory,
		InFlightCapacityBytes:   plan.InFlightCapacityBytes,
		RecommendedQueueDepth:   plan.RecommendedQueueDepth,
	}
	candidate.Reasons = rejectionReasons(req, candidate)
	candidate.Rejected = len(candidate.Reasons) > 0
	return candidate
}

func rejectionReasons(req OptimizationRequest, c CandidateConfig) []string {
	var reasons []string
	if !req.AllowRealtime && c.SelectedDataProfile == DataProfileRealtime {
		reasons = append(reasons, "realtime route disallowed by policy")
	}
	if !req.AllowBulk && c.SelectedDataProfile == DataProfileBulk {
		reasons = append(reasons, "bulk route disallowed by policy")
	}
	if req.MaxMemoryBytes > 0 && c.EstimatedMemoryBytes > req.MaxMemoryBytes {
		reasons = append(reasons, fmt.Sprintf("estimated memory %d exceeds max %d", c.EstimatedMemoryBytes, req.MaxMemoryBytes))
	}
	if req.MinThroughputMbps > 0 && c.EstimatedThroughputMbps < req.MinThroughputMbps {
		reasons = append(reasons, fmt.Sprintf("estimated throughput %.2f Mbps below min %.2f Mbps", c.EstimatedThroughputMbps, req.MinThroughputMbps))
	}
	if req.MaxLatencyMillis > 0 && c.EstimatedLatencyMillis > req.MaxLatencyMillis {
		reasons = append(reasons, fmt.Sprintf("estimated latency %.2f ms exceeds max %.2f ms", c.EstimatedLatencyMillis, req.MaxLatencyMillis))
	}
	return reasons
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
