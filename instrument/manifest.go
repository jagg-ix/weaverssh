package instrument

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
)

const (
	ManifestVersion = "weaverssh.instrumentability.v1"
	DefaultPrefix   = "weaverssh"
	PhysicalMode    = "single-ssh-x11-websocket-chain"
	ProviderEBPF    = "ebpf"
)

type ProbePoint struct {
	ID               string   `json:"id"`
	Provider         string   `json:"provider"`
	Component        string   `json:"component"`
	EventType        string   `json:"event_type"`
	Purpose          string   `json:"purpose"`
	AttachmentKind   string   `json:"attachment_kind"`
	AttachTo         []string `json:"attach_to"`
	Fields           []string `json:"fields"`
	MQTTTopic        string   `json:"mqtt_topic"`
	RequiredAccess   string   `json:"required_access"`
	EnabledByDefault bool     `json:"enabled_by_default"`
	Notes            string   `json:"notes,omitempty"`
}

type ToolStatus struct {
	Name     string `json:"name"`
	Found    bool   `json:"found"`
	Path     string `json:"path,omitempty"`
	Required bool   `json:"required"`
	Purpose  string `json:"purpose"`
}

type KernelFeature struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Path      string `json:"path,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

type SupportStatus struct {
	OK                  bool            `json:"ok"`
	Provider            string          `json:"provider"`
	Supported           bool            `json:"supported"`
	Platform            string          `json:"platform"`
	KernelRelease       string          `json:"kernel_release,omitempty"`
	BPFfsMounted        bool            `json:"bpffs_mounted,omitempty"`
	TracingFSMounted    bool            `json:"tracingfs_mounted,omitempty"`
	UnprivilegedBPF     string          `json:"unprivileged_bpf,omitempty"`
	Tools               []ToolStatus    `json:"tools"`
	Features            []KernelFeature `json:"features"`
	Missing             []string        `json:"missing,omitempty"`
	NextAction          string          `json:"next_action"`
	ProductionSafeByDef bool            `json:"production_safe_by_default"`
}

type AttachPlan struct {
	Version        string        `json:"version"`
	Provider       string        `json:"provider"`
	Profile        string        `json:"profile"`
	Prefix         string        `json:"prefix"`
	PhysicalMode   string        `json:"physical_mode"`
	Chain          []string      `json:"chain,omitempty"`
	Safety         []string      `json:"safety"`
	RequiredAccess []string      `json:"required_access"`
	ProbePoints    []ProbePoint  `json:"probe_points"`
	Commands       []PlanCommand `json:"commands"`
}

type PlanCommand struct {
	Tool         string   `json:"tool"`
	Command      []string `json:"command"`
	Description  string   `json:"description"`
	RequiresRoot bool     `json:"requires_root"`
}

func SupportedProviders() []string {
	return []string{ProviderEBPF}
}

func NormalizeProvider(provider string) (string, error) {
	provider = strings.TrimSpace(strings.ToLower(provider))
	if provider == "" {
		provider = ProviderEBPF
	}
	switch provider {
	case ProviderEBPF:
		return provider, nil
	default:
		return "", fmt.Errorf("unsupported instrumentation provider %q; supported providers: %s", provider, strings.Join(SupportedProviders(), ", "))
	}
}

func DefaultProbePoints(provider, prefix string) ([]ProbePoint, error) {
	provider, err := NormalizeProvider(provider)
	if err != nil {
		return nil, err
	}
	prefix = cleanPrefix(prefix)
	if provider != ProviderEBPF {
		return nil, fmt.Errorf("unsupported instrumentation provider %q", provider)
	}
	return []ProbePoint{
		{
			ID:               "wv.instrument.ebpf.process.lifecycle",
			Provider:         provider,
			Component:        "runtime",
			EventType:        "process_lifecycle",
			Purpose:          "correlate wv process start/exit with tunnel and broker events",
			AttachmentKind:   "tracepoint",
			AttachTo:         []string{"sched/sched_process_exec", "sched/sched_process_exit"},
			Fields:           []string{"pid", "ppid", "comm", "filename", "exit_code"},
			MQTTTopic:        topic(prefix, "instrument", provider, "runtime/process_lifecycle"),
			RequiredAccess:   "CAP_BPF or root, plus tracefs access on Linux",
			EnabledByDefault: true,
		},
		{
			ID:               "wv.instrument.ebpf.ssh.socket.connect",
			Provider:         provider,
			Component:        "transport",
			EventType:        "ssh_socket_connect",
			Purpose:          "observe the single SSH socket opened for each adjacent chain hop",
			AttachmentKind:   "tracepoint",
			AttachTo:         []string{"syscalls/sys_enter_connect", "syscalls/sys_exit_connect"},
			Fields:           []string{"pid", "comm", "fd", "family", "dst_addr", "dst_port", "ret"},
			MQTTTopic:        topic(prefix, "instrument", provider, "transport/ssh_socket_connect"),
			RequiredAccess:   "CAP_BPF or root, plus tracefs access on Linux",
			EnabledByDefault: true,
		},
		{
			ID:               "wv.instrument.ebpf.tcp.state",
			Provider:         provider,
			Component:        "transport",
			EventType:        "tcp_state",
			Purpose:          "track TCP state transitions, reconnects, resets, and abnormal closes for the SSH-carried chain",
			AttachmentKind:   "tracepoint",
			AttachTo:         []string{"sock/inet_sock_set_state"},
			Fields:           []string{"pid", "comm", "oldstate", "newstate", "saddr", "daddr", "sport", "dport"},
			MQTTTopic:        topic(prefix, "instrument", provider, "transport/tcp_state"),
			RequiredAccess:   "CAP_BPF or root, plus tracefs access on Linux",
			EnabledByDefault: true,
		},
		{
			ID:               "wv.instrument.ebpf.socket.bytes",
			Provider:         provider,
			Component:        "relay",
			EventType:        "socket_bytes",
			Purpose:          "sample per-process send/receive volume for relay, pub-sub, and VFS traffic without decoding payloads",
			AttachmentKind:   "tracepoint",
			AttachTo:         []string{"syscalls/sys_enter_sendto", "syscalls/sys_exit_recvfrom", "syscalls/sys_enter_sendmsg", "syscalls/sys_exit_recvmsg"},
			Fields:           []string{"pid", "comm", "fd", "bytes", "direction", "ret"},
			MQTTTopic:        topic(prefix, "instrument", provider, "relay/socket_bytes"),
			RequiredAccess:   "CAP_BPF or root, plus tracefs access on Linux",
			EnabledByDefault: false,
			Notes:            "Use sampling/rate limits on busy production hosts.",
		},
		{
			ID:               "wv.instrument.ebpf.cgroup.connect.policy",
			Provider:         provider,
			Component:        "policy",
			EventType:        "connect_policy",
			Purpose:          "optionally enforce or audit approved outbound connection domains at the cgroup boundary",
			AttachmentKind:   "cgroup/connect4+connect6",
			AttachTo:         []string{"cgroup/connect4", "cgroup/connect6"},
			Fields:           []string{"cgroup_id", "pid", "comm", "dst_addr", "dst_port", "decision"},
			MQTTTopic:        topic(prefix, "instrument", provider, "policy/connect_policy"),
			RequiredAccess:   "root or delegated cgroup BPF loader with CAP_BPF/CAP_NET_ADMIN",
			EnabledByDefault: false,
			Notes:            "Planner only; policy loading must be explicit and audited.",
		},
		{
			ID:               "wv.instrument.semantic.pubsub",
			Provider:         "semantic",
			Component:        "pubsub",
			EventType:        "semantic_event",
			Purpose:          "correlate provider samples with wv pubsub events and mesh envelopes",
			AttachmentKind:   "userspace-correlation",
			AttachTo:         []string{topic(prefix, "pubsub", "broker", "publish"), topic(prefix, "pubsub", "mesh", "forward")},
			Fields:           []string{"event_id", "chain_id", "node_id", "origin_node_id", "topic", "hop", "path"},
			MQTTTopic:        topic(prefix, "instrument", "semantic", "pubsub/semantic_event"),
			RequiredAccess:   "wv pubsub access; no kernel privilege",
			EnabledByDefault: true,
			Notes:            "This is not a kernel attachment; it provides semantic correlation for provider samples.",
		},
	}, nil
}

func DetectSupport(provider string) (SupportStatus, error) {
	provider, err := NormalizeProvider(provider)
	if err != nil {
		return SupportStatus{}, err
	}
	platform := runtime.GOOS + "/" + runtime.GOARCH
	st := SupportStatus{Provider: provider, Platform: platform, ProductionSafeByDef: true}
	if provider != ProviderEBPF {
		return st, fmt.Errorf("unsupported instrumentation provider %q", provider)
	}
	st.Supported = runtime.GOOS == "linux"
	st.KernelRelease = readTrimmed("/proc/sys/kernel/osrelease")
	st.BPFfsMounted = pathExists("/sys/fs/bpf")
	st.TracingFSMounted = pathExists("/sys/kernel/tracing") || pathExists("/sys/kernel/debug/tracing")
	st.UnprivilegedBPF = readTrimmed("/proc/sys/kernel/unprivileged_bpf_disabled")
	st.Tools = detectEBPFTools()
	st.Features = []KernelFeature{
		{Name: "bpffs", Available: st.BPFfsMounted, Path: "/sys/fs/bpf"},
		{Name: "tracefs", Available: st.TracingFSMounted, Path: "/sys/kernel/tracing"},
		{Name: "bpf syscall", Available: runtime.GOOS == "linux", Detail: "requires kernel support and loader privileges"},
	}
	if !st.Supported {
		st.OK = false
		st.NextAction = "eBPF attach is Linux-only; use semantic pubsub/log correlation on this platform."
		st.Missing = []string{"linux kernel"}
		return st, nil
	}
	if !st.BPFfsMounted {
		st.Missing = append(st.Missing, "/sys/fs/bpf")
	}
	if !st.TracingFSMounted {
		st.Missing = append(st.Missing, "tracefs")
	}
	if !toolFound(st.Tools, "bpftool") && !toolFound(st.Tools, "bpftrace") {
		st.Missing = append(st.Missing, "bpftool or bpftrace")
	}
	st.OK = len(st.Missing) == 0
	if st.OK {
		st.NextAction = "Host can run provider collectors; use wv instrument plan before loading any privileged program."
	} else {
		st.NextAction = "Install/enable missing provider tooling or run semantic-only pubsub instrumentation."
	}
	return st, nil
}

func BuildPlan(provider, profile, prefix string, chain []string) (AttachPlan, error) {
	provider, err := NormalizeProvider(provider)
	if err != nil {
		return AttachPlan{}, err
	}
	profile = strings.TrimSpace(strings.ToLower(profile))
	if profile == "" {
		profile = "minimal"
	}
	probes, err := DefaultProbePoints(provider, prefix)
	if err != nil {
		return AttachPlan{}, err
	}
	selected := make([]ProbePoint, 0, len(probes))
	for _, probe := range probes {
		switch profile {
		case "minimal":
			if probe.EnabledByDefault {
				selected = append(selected, probe)
			}
		case "socket":
			if probe.Component == "transport" || probe.Component == "runtime" || probe.Component == "pubsub" {
				selected = append(selected, probe)
			}
		case "full":
			selected = append(selected, probe)
		default:
			return AttachPlan{}, fmt.Errorf("unsupported instrumentation profile %q; expected minimal, socket, or full", profile)
		}
	}
	return AttachPlan{
		Version:      ManifestVersion,
		Provider:     provider,
		Profile:      profile,
		Prefix:       cleanPrefix(prefix),
		PhysicalMode: PhysicalMode,
		Chain:        cleanChain(chain),
		Safety: []string{
			"do not decode payload bytes in provider probes",
			"prefer stable attachment points over kernel-version-sensitive hooks",
			"publish only metadata, counters, timing, and policy decisions",
			"do not load enforcement programs unless explicitly approved and audited",
		},
		RequiredAccess: []string{"provider-specific host support", "Linux kernel for eBPF provider", "CAP_BPF or root for kernel probes", "tracefs access", "bpftool or bpftrace for eBPF loading/inspection"},
		ProbePoints:    selected,
		Commands:       planCommands(provider, profile),
	}, nil
}

func Script(provider, profile, format string) (string, error) {
	provider, err := NormalizeProvider(provider)
	if err != nil {
		return "", err
	}
	format = strings.TrimSpace(strings.ToLower(format))
	if format == "" {
		format = "bpftrace"
	}
	if provider != ProviderEBPF || format != "bpftrace" {
		return "", fmt.Errorf("unsupported script provider/format %q/%q", provider, format)
	}
	plan, err := BuildPlan(provider, profile, DefaultPrefix, nil)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("#!/usr/bin/env bpftrace\n")
	b.WriteString("/* weaverssh metadata-only instrumentation smoke probe. Run with elevated privileges on Linux. */\n")
	b.WriteString("BEGIN { printf(\"weaverssh instrument provider=")
	b.WriteString(plan.Provider)
	b.WriteString(" profile=")
	b.WriteString(plan.Profile)
	b.WriteString("\\n\"); }\n\n")
	b.WriteString("tracepoint:syscalls:sys_enter_connect /comm == \"wv\" || comm == \"ssh\"/ { printf(\"connect pid=%d comm=%s fd=%d\\n\", pid, comm, args->fd); }\n")
	b.WriteString("tracepoint:sock:inet_sock_set_state /comm == \"wv\" || comm == \"ssh\"/ { printf(\"tcp_state pid=%d comm=%s old=%d new=%d\\n\", pid, comm, args->oldstate, args->newstate); }\n")
	if plan.Profile == "socket" || plan.Profile == "full" {
		b.WriteString("tracepoint:syscalls:sys_exit_recvfrom /comm == \"wv\" || comm == \"ssh\"/ { if (args->ret > 0) { @rx[comm] = sum(args->ret); } }\n")
		b.WriteString("tracepoint:syscalls:sys_enter_sendto /comm == \"wv\" || comm == \"ssh\"/ { @tx[comm] = sum(args->len); }\n")
		b.WriteString("\ninterval:s:10 { print(@rx); print(@tx); clear(@rx); clear(@tx); }\n")
	}
	return b.String(), nil
}

func planCommands(provider, profile string) []PlanCommand {
	cmds := []PlanCommand{
		{Tool: "bpftool", Command: []string{"bpftool", "feature", "probe"}, Description: "inspect kernel/helper/map support before loading eBPF programs", RequiresRoot: true},
		{Tool: "bpftrace", Command: []string{"bpftrace", "-l", "tracepoint:syscalls:sys_enter_connect"}, Description: "verify tracepoint visibility", RequiresRoot: false},
		{Tool: "wv", Command: []string{"wv", "pubsub", "subscribe", "--topic", cleanPrefix(DefaultPrefix) + "/instrument/#"}, Description: "observe instrumentation metadata events through the weaverssh pub-sub bus", RequiresRoot: false},
	}
	if provider == ProviderEBPF && profile == "full" {
		cmds = append(cmds, PlanCommand{Tool: "bpftool", Command: []string{"bpftool", "prog", "show"}, Description: "audit loaded eBPF programs", RequiresRoot: true})
	}
	return cmds
}

func detectEBPFTools() []ToolStatus {
	tools := []ToolStatus{
		{Name: "bpftool", Required: false, Purpose: "inspect/load pinned eBPF objects"},
		{Name: "bpftrace", Required: false, Purpose: "ad hoc tracepoint smoke probes"},
		{Name: "clang", Required: false, Purpose: "compile libbpf/C eBPF programs"},
		{Name: "llc", Required: false, Purpose: "LLVM BPF backend"},
		{Name: "pahole", Required: false, Purpose: "BTF generation/debugging"},
	}
	for i := range tools {
		if p, err := exec.LookPath(tools[i].Name); err == nil {
			tools[i].Found = true
			tools[i].Path = p
		}
	}
	return tools
}

func toolFound(tools []ToolStatus, name string) bool {
	for _, tool := range tools {
		if tool.Name == name && tool.Found {
			return true
		}
	}
	return false
}

func topic(prefix string, parts ...string) string {
	items := append([]string{cleanPrefix(prefix)}, parts...)
	return strings.Join(items, "/")
}

func cleanPrefix(prefix string) string {
	prefix = strings.Trim(strings.TrimSpace(prefix), "/")
	if prefix == "" {
		return DefaultPrefix
	}
	return prefix
}

func cleanChain(chain []string) []string {
	out := make([]string, 0, len(chain))
	seen := map[string]struct{}{}
	for _, node := range chain {
		node = strings.Trim(strings.TrimSpace(node), "/")
		if node == "" {
			continue
		}
		if _, ok := seen[node]; ok {
			continue
		}
		seen[node] = struct{}{}
		out = append(out, node)
	}
	return out
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func readTrimmed(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func ProbeIDs(probes []ProbePoint) []string {
	ids := make([]string, 0, len(probes))
	for _, probe := range probes {
		ids = append(ids, probe.ID)
	}
	sort.Strings(ids)
	return ids
}
