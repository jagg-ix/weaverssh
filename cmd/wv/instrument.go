package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"weaverssh/instrument"
)

func cmdInstrument(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "status", "check", "doctor":
			return cmdInstrumentStatus(args[1:])
		case "probes", "manifest", "spec":
			return cmdInstrumentProbes(args[1:])
		case "plan":
			return cmdInstrumentPlan(args[1:])
		case "script", "bpftrace":
			return cmdInstrumentScript(args[1:])
		case "providers":
			return cmdInstrumentProviders(args[1:])
		case "help", "-h", "--help":
			printInstrumentHelp()
			return 0
		}
		if !strings.HasPrefix(args[0], "-") {
			fmt.Fprintf(os.Stderr, "instrument: unknown command %q\n", args[0])
			printInstrumentHelp()
			return 2
		}
	}
	printInstrumentHelp()
	return 2
}

func cmdInstrumentStatus(args []string) int {
	fs := flag.NewFlagSet("instrument status", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON")
	provider := fs.String("provider", instrument.ProviderEBPF, "instrumentation provider")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv instrument status [--provider ebpf] [--json]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	status, err := instrument.DetectSupport(*provider)
	if err != nil {
		fmt.Fprintf(os.Stderr, "instrument status: %v\n", err)
		return 2
	}
	if *jsonOut {
		return printJSON(status)
	}
	fmt.Printf("provider:  %s\n", status.Provider)
	fmt.Printf("supported: %t\n", status.Supported)
	fmt.Printf("ready:     %t\n", status.OK)
	fmt.Printf("platform:  %s\n", status.Platform)
	if status.KernelRelease != "" {
		fmt.Printf("kernel:    %s\n", status.KernelRelease)
	}
	if status.Provider == instrument.ProviderEBPF {
		fmt.Printf("bpffs:     %t\n", status.BPFfsMounted)
		fmt.Printf("tracefs:   %t\n", status.TracingFSMounted)
		if status.UnprivilegedBPF != "" {
			fmt.Printf("unprivileged_bpf_disabled: %s\n", status.UnprivilegedBPF)
		}
	}
	fmt.Println("tools:")
	for _, tool := range status.Tools {
		state := "missing"
		if tool.Found {
			state = tool.Path
		}
		fmt.Printf("  - %-8s %s\n", tool.Name, state)
	}
	if len(status.Missing) > 0 {
		fmt.Printf("missing:   %s\n", strings.Join(status.Missing, ", "))
	}
	fmt.Printf("next:      %s\n", status.NextAction)
	if !status.OK {
		return 1
	}
	return 0
}

func cmdInstrumentProbes(args []string) int {
	fs := flag.NewFlagSet("instrument probes", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON")
	provider := fs.String("provider", instrument.ProviderEBPF, "instrumentation provider")
	prefix := fs.String("prefix", instrument.DefaultPrefix, "MQTT topic prefix")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv instrument probes [--provider ebpf] [--prefix PREFIX] [--json]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	probes, err := instrument.DefaultProbePoints(*provider, *prefix)
	if err != nil {
		fmt.Fprintf(os.Stderr, "instrument probes: %v\n", err)
		return 2
	}
	if *jsonOut {
		return printJSON(map[string]any{"version": instrument.ManifestVersion, "provider": *provider, "probes": probes})
	}
	fmt.Printf("version:  %s\n", instrument.ManifestVersion)
	fmt.Printf("provider: %s\n", *provider)
	for _, probe := range probes {
		defaultState := "optional"
		if probe.EnabledByDefault {
			defaultState = "default"
		}
		fmt.Printf("- %s [%s] provider=%s component=%s event=%s\n", probe.ID, defaultState, probe.Provider, probe.Component, probe.EventType)
		fmt.Printf("  attach: %s %s\n", probe.AttachmentKind, strings.Join(probe.AttachTo, ", "))
		fmt.Printf("  topic:  %s\n", probe.MQTTTopic)
	}
	return 0
}

func cmdInstrumentPlan(args []string) int {
	fs := flag.NewFlagSet("instrument plan", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON")
	provider := fs.String("provider", instrument.ProviderEBPF, "instrumentation provider")
	prefix := fs.String("prefix", instrument.DefaultPrefix, "MQTT topic prefix")
	profile := fs.String("profile", "minimal", "instrumentation profile: minimal, socket, or full")
	chainText := fs.String("chain", "", "comma-separated chain nodes, e.g. origin,node1,node2")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv instrument plan [--provider ebpf] [--profile minimal|socket|full] [--chain origin,node1,node2] [--json]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	plan, err := instrument.BuildPlan(*provider, *profile, *prefix, parseCSVNodes(*chainText))
	if err != nil {
		fmt.Fprintf(os.Stderr, "instrument plan: %v\n", err)
		return 2
	}
	if *jsonOut {
		return printJSON(plan)
	}
	fmt.Printf("version:      %s\n", plan.Version)
	fmt.Printf("provider:     %s\n", plan.Provider)
	fmt.Printf("profile:      %s\n", plan.Profile)
	fmt.Printf("physical:     %s\n", plan.PhysicalMode)
	if len(plan.Chain) > 0 {
		fmt.Printf("chain:        %s\n", strings.Join(plan.Chain, " -> "))
	}
	fmt.Println("safety:")
	for _, item := range plan.Safety {
		fmt.Printf("  - %s\n", item)
	}
	fmt.Println("probe points:")
	for _, probe := range plan.ProbePoints {
		fmt.Printf("  - %s provider=%s attach=%s event=%s topic=%s\n", probe.ID, probe.Provider, probe.AttachmentKind, probe.EventType, probe.MQTTTopic)
	}
	fmt.Println("commands:")
	for _, cmd := range plan.Commands {
		priv := "user"
		if cmd.RequiresRoot {
			priv = "root/provider-capability"
		}
		fmt.Printf("  - [%s] %s\n", priv, strings.Join(cmd.Command, " "))
	}
	return 0
}

func cmdInstrumentScript(args []string) int {
	fs := flag.NewFlagSet("instrument script", flag.ContinueOnError)
	provider := fs.String("provider", instrument.ProviderEBPF, "instrumentation provider")
	profile := fs.String("profile", "minimal", "script profile: minimal, socket, or full")
	format := fs.String("format", "bpftrace", "script format")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv instrument script [--provider ebpf] [--format bpftrace] [--profile minimal|socket|full]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	script, err := instrument.Script(*provider, *profile, *format)
	if err != nil {
		fmt.Fprintf(os.Stderr, "instrument script: %v\n", err)
		return 2
	}
	fmt.Print(script)
	return 0
}

func cmdInstrumentProviders(args []string) int {
	fs := flag.NewFlagSet("instrument providers", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv instrument providers [--json]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	providers := instrument.SupportedProviders()
	if *jsonOut {
		return printJSON(map[string]any{"providers": providers})
	}
	fmt.Println("providers:")
	for _, provider := range providers {
		fmt.Printf("  - %s\n", provider)
	}
	return 0
}

func printInstrumentHelp() {
	fmt.Print(`wv instrument - inspect and plan provider-based instrumentability for weaverssh

Usage:
  wv instrument providers [--json]
  wv instrument status [--provider ebpf] [--json]
  wv instrument probes [--provider ebpf] [--prefix PREFIX] [--json]
  wv instrument plan [--provider ebpf] [--profile minimal|socket|full] [--chain origin,node1,node2] [--json]
  wv instrument script [--provider ebpf] [--format bpftrace] [--profile minimal|socket|full]

Notes:
  Providers are pluggable. The current provider is ebpf, which is Linux-only and
  usually requires root or CAP_BPF for kernel attachments. Default commands do
  not load privileged programs; they detect support and generate metadata-only
  plans. Use wv pubsub for semantic correlation events.
`)
}
