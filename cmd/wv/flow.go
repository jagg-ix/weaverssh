package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"weaverssh/flowcontrol"
)

func cmdFlow(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "profiles", "list":
			return cmdFlowProfiles(args[1:])
		case "plan", "bench-plan", "benchmark-plan":
			return cmdFlowPlan(args[1:])
		case "optimize", "route", "select":
			return cmdFlowOptimize(args[1:])
		case "validate", "check":
			return cmdFlowValidate(args[1:])
		case "help", "-h", "--help":
			printFlowHelp()
			return 0
		}
		if !strings.HasPrefix(args[0], "-") {
			fmt.Fprintf(os.Stderr, "flow: unknown command %q\n", args[0])
			printFlowHelp()
			return 2
		}
	}
	printFlowHelp()
	return 2
}

func cmdFlowProfiles(args []string) int {
	fs := flag.NewFlagSet("flow profiles", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv flow profiles [--json]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	profiles := make([]flowcontrol.Profile, 0)
	for _, name := range flowcontrol.Names() {
		p, _ := flowcontrol.Builtin(name)
		profiles = append(profiles, p)
	}
	if *jsonOut {
		return printJSON(map[string]any{"version": flowcontrol.ContractVersion, "profiles": profiles})
	}
	fmt.Printf("version: %s\n", flowcontrol.ContractVersion)
	for _, p := range profiles {
		fmt.Printf("- %s ssh=%d ws_frame=%d relay=%d queue=%d tcp_nodelay=%t\n",
			p.Name, p.SSHSocketBufferBytes, p.WebSocketFrameBytes, p.RelayReadBytes, p.QueueDepth, p.TCPNoDelay)
	}
	return 0
}

func cmdFlowPlan(args []string) int {
	fs := flag.NewFlagSet("flow plan", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON")
	profile := fs.String("profile", flowcontrol.ProfileBalanced, "flow profile: realtime, balanced, or bulk")
	bandwidth := fs.Float64("bandwidth-mbps", 100, "expected path bandwidth in Mbps")
	rttText := fs.String("rtt", flowcontrol.DefaultRTT.String(), "expected round-trip time, e.g. 40ms")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv flow plan [--profile realtime|balanced|bulk] [--bandwidth-mbps N] [--rtt 40ms] [--json]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	rtt, err := flowcontrol.ParseDurationText(*rttText)
	if err != nil {
		fmt.Fprintf(os.Stderr, "flow plan: invalid --rtt: %v\n", err)
		return 2
	}
	plan, err := flowcontrol.BuildPlan(*profile, *bandwidth, rtt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "flow plan: %v\n", err)
		return 2
	}
	if *jsonOut {
		return printJSON(plan)
	}
	printFlowPlan(plan)
	return 0
}

func cmdFlowOptimize(args []string) int {
	fs := flag.NewFlagSet("flow optimize", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON")
	policy := fs.String("policy", flowcontrol.PolicyBalanced, "targeted policy: latency, throughput, balanced, or reliability")
	payloadBytes := fs.Int("payload-bytes", 4096, "representative payload size in bytes")
	bandwidth := fs.Float64("bandwidth-mbps", 100, "measured or expected path bandwidth in Mbps")
	rttText := fs.String("rtt", flowcontrol.DefaultRTT.String(), "measured or expected round-trip time, e.g. 40ms")
	hops := fs.Int("hops", 1, "number of SSH/X11/WebSocket chain hops")
	lossPercent := fs.Float64("loss-percent", 0, "observed packet loss percentage")
	streams := fs.Int("streams", 1, "expected concurrent streams")
	maxMemory := fs.Int64("max-memory-bytes", 4*1024*1024, "maximum local buffering memory for this flow")
	minThroughput := fs.Float64("min-throughput-mbps", 0, "optional minimum accepted throughput in Mbps")
	maxLatency := fs.Float64("max-latency-ms", 0, "optional maximum accepted latency in milliseconds")
	noRealtime := fs.Bool("no-realtime", false, "disallow realtime data profile")
	noBulk := fs.Bool("no-bulk", false, "disallow bulk data profile")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv flow optimize [--policy latency|throughput|balanced|reliability] [--payload-bytes N] [--bandwidth-mbps N] [--rtt 40ms] [--json]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	rtt, err := flowcontrol.ParseDurationText(*rttText)
	if err != nil {
		fmt.Fprintf(os.Stderr, "flow optimize: invalid --rtt: %v\n", err)
		return 2
	}
	if *noRealtime && *noBulk {
		fmt.Fprintln(os.Stderr, "flow optimize: --no-realtime and --no-bulk cannot both be set")
		return 2
	}
	req := flowcontrol.OptimizationRequest{
		Policy:            *policy,
		PayloadBytes:      *payloadBytes,
		BandwidthMbps:     *bandwidth,
		RTT:               rtt,
		HopCount:          *hops,
		LossPercent:       *lossPercent,
		ConcurrentStreams: *streams,
		MaxMemoryBytes:    *maxMemory,
		MinThroughputMbps: *minThroughput,
		MaxLatencyMillis:  *maxLatency,
		AllowRealtime:     !*noRealtime,
		AllowBulk:         !*noBulk,
	}
	decision, err := flowcontrol.Optimize(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "flow optimize: %v\n", err)
		return 1
	}
	if *jsonOut {
		return printJSON(decision)
	}
	printFlowOptimization(decision)
	return 0
}

func cmdFlowValidate(args []string) int {
	fs := flag.NewFlagSet("flow validate", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON")
	profile := fs.String("profile", flowcontrol.ProfileBalanced, "flow profile: realtime, balanced, or bulk")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv flow validate [--profile realtime|balanced|bulk] [--json]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	p, err := flowcontrol.Builtin(*profile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "flow validate: %v\n", err)
		return 2
	}
	reasons := p.Validate()
	result := map[string]any{
		"version": flowcontrol.ContractVersion,
		"profile": p,
		"ok":      len(reasons) == 0,
		"reasons": reasons,
	}
	if *jsonOut {
		return printJSON(result)
	}
	fmt.Printf("profile: %s\n", p.Name)
	fmt.Printf("matched: %t\n", len(reasons) == 0)
	if len(reasons) > 0 {
		fmt.Println("mismatches:")
		for _, reason := range reasons {
			fmt.Printf("  - %s\n", reason)
		}
		return 1
	}
	fmt.Println("next: profile is safe for matched SSH socket, WebSocket frame, and relay chunk benchmarking")
	return 0
}

func printFlowOptimization(decision flowcontrol.OptimizationDecision) {
	s := decision.Selected
	fmt.Printf("version:        %s\n", decision.Version)
	fmt.Printf("algorithm:      %s\n", decision.Algorithm)
	fmt.Printf("policy:         %s\n", decision.Policy)
	fmt.Printf("selected:       flow=%s transport=%s route=%s data=%s\n", s.FlowProfile, s.TransportMode, s.RoutePolicy, s.SelectedDataProfile)
	fmt.Printf("score:          %.4f\n", s.Score)
	fmt.Printf("threshold:      realtime<=%d bytes\n", s.RealtimeThresholdBytes)
	fmt.Printf("latency:        %.2f ms\n", s.EstimatedLatencyMillis)
	fmt.Printf("throughput:     %.2f Mbps\n", s.EstimatedThroughputMbps)
	fmt.Printf("reliability:    %.4f\n", s.EstimatedReliability)
	fmt.Printf("memory:         %d bytes\n", s.EstimatedMemoryBytes)
	fmt.Printf("queue:          recommended=%d in_flight=%d bytes\n", s.RecommendedQueueDepth, s.InFlightCapacityBytes)
	if len(decision.Warnings) > 0 {
		fmt.Println("warnings:")
		for _, warning := range decision.Warnings {
			fmt.Printf("  - %s\n", warning)
		}
	}
	fmt.Println("commands:")
	for _, command := range decision.Commands {
		fmt.Printf("  - %s\n", command)
	}
	fmt.Println("alternatives:")
	limit := len(decision.Alternatives)
	if limit > 5 {
		limit = 5
	}
	for i := 0; i < limit; i++ {
		alt := decision.Alternatives[i]
		status := "ok"
		if alt.Rejected {
			status = "rejected"
		}
		fmt.Printf("  - [%s] score=%.4f flow=%s transport=%s route=%s data=%s latency=%.2fms throughput=%.2fMbps\n",
			status, alt.Score, alt.FlowProfile, alt.TransportMode, alt.RoutePolicy, alt.SelectedDataProfile, alt.EstimatedLatencyMillis, alt.EstimatedThroughputMbps)
	}
}

func printFlowPlan(plan flowcontrol.Plan) {
	p := plan.Profile
	fmt.Printf("version:        %s\n", plan.Version)
	fmt.Printf("profile:        %s\n", p.Name)
	fmt.Printf("matched:        %t\n", plan.Matched)
	fmt.Printf("ssh socket:     %d bytes\n", p.SSHSocketBufferBytes)
	fmt.Printf("x11 packet max: %d bytes\n", p.X11PacketMaxBytes)
	fmt.Printf("ws buffers:     read=%d write=%d frame=%d bytes\n", p.WebSocketReadBufferBytes, p.WebSocketWriteBufferBytes, p.WebSocketFrameBytes)
	fmt.Printf("relay chunk:    %d bytes\n", p.RelayReadBytes)
	fmt.Printf("queue depth:    %d frames (%d bytes in flight)\n", p.QueueDepth, plan.InFlightCapacityBytes)
	fmt.Printf("tcp nodelay:    %t\n", p.TCPNoDelay)
	fmt.Printf("bdp:            %d bytes\n", plan.BDPBytes)
	fmt.Printf("recommended q:  %d frames\n", plan.RecommendedQueueDepth)
	fmt.Printf("drain estimate: %d ms\n", plan.EstimatedDrainTimeMillis)
	fmt.Printf("bench payloads: %s\n", joinInts(plan.BenchmarkPayloadBytes))
	if len(plan.MismatchReasons) > 0 {
		fmt.Println("mismatches:")
		for _, reason := range plan.MismatchReasons {
			fmt.Printf("  - %s\n", reason)
		}
	}
	if len(plan.Warnings) > 0 {
		fmt.Println("warnings:")
		for _, warning := range plan.Warnings {
			fmt.Printf("  - %s\n", warning)
		}
	}
	fmt.Println("commands:")
	for _, command := range plan.BenchmarkCommands {
		fmt.Printf("  - %s\n", command)
	}
}

func joinInts(values []int) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, fmt.Sprintf("%d", value))
	}
	return strings.Join(parts, ",")
}

func printFlowHelp() {
	fmt.Print(`wv flow - inspect SSH/WebSocket relay buffering and benchmark profiles

Usage:
  wv flow profiles [--json]
  wv flow plan [--profile realtime|balanced|bulk] [--bandwidth-mbps N] [--rtt 40ms] [--json]
  wv flow optimize [--policy latency|throughput|balanced|reliability] [--payload-bytes N] [--bandwidth-mbps N] [--rtt 40ms] [--json]
  wv flow validate [--profile realtime|balanced|bulk] [--json]

The flow contract aligns SSH socket buffering, WebSocket frame payloads, relay
read chunks, and bounded in-flight queue depth before benchmarking or relay use.
`)
}
