package extension

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

const (
	// EBPFEventVersion identifies the fixed binary hook-event ABI.
	EBPFEventVersion = "weaverssh.ebpf-event.v1"
	// EBPFRuntimeKind identifies hooks executed by an eBPF VM runtime.
	EBPFRuntimeKind = "ebpf"
	// EBPFRuntimePinned selects a program already pinned in the host runtime.
	EBPFRuntimePinned = "pinned"

	EBPFEventSize = 248

	EBPFDecisionAllow uint32 = 0

	ebpfOffsetMagic          = 0
	ebpfOffsetABIVersion     = 4
	ebpfOffsetPoint          = 6
	ebpfOffsetServiceID      = 8
	ebpfOffsetFlags          = 10
	ebpfOffsetMetadataBytes  = 12
	ebpfOffsetOccurredAt     = 16
	ebpfOffsetSessionDigest  = 24
	ebpfOffsetLocalDigest    = 56
	ebpfOffsetPeerDigest     = 88
	ebpfOffsetTargetDigest   = 120
	ebpfOffsetServiceDigest  = 152
	ebpfOffsetMetadataDigest = 184
	ebpfOffsetAttrsDigest    = 216

	ebpfFlagMetadata   uint16 = 1 << 0
	ebpfFlagAttributes uint16 = 1 << 1
	maxEBPFProgramRef         = 4 << 10
)

var ebpfEventMagic = [4]byte{'W', 'V', 'E', 'B'}

var ErrEBPFUnsupported = errors.New("extension: native pinned eBPF runtime is not enabled for this build or operating system")

// EBPFRuntimeRequest is one invocation of a program in an eBPF VM runtime.
// Program is a runtime-specific stable reference. The built-in pinned runtime
// interprets it as a pinned program path or name.
type EBPFRuntimeRequest struct {
	Program string
	Input   []byte
}

// EBPFRuntime executes eBPF bytecode using a host implementation. This interface
// is deliberately independent from Linux attachment APIs: an implementation may
// use the Linux kernel, Microsoft eBPF for Windows, or another verified VM.
type EBPFRuntime interface {
	Name() string
	Run(context.Context, EBPFRuntimeRequest) (uint32, error)
}

// PinnedRuntime executes a program already loaded and pinned by platform tooling.
// Linux resolves pins through bpffs. Microsoft eBPF for Windows resolves pinned
// objects through its global object model. No attachment is created by weaverssh.
type PinnedRuntime struct{}

func (PinnedRuntime) Name() string { return EBPFRuntimePinned }

func (PinnedRuntime) Run(ctx context.Context, request EBPFRuntimeRequest) (uint32, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return runNativePinnedEBPF(ctx, request.Program, request.Input)
}

// NativePinnedEBPFAvailable reports whether this binary includes the built-in
// pinned-program provider. It is enabled by building with -tags ebpf on Linux
// or Microsoft Windows.
func NativePinnedEBPFAvailable() bool { return nativePinnedEBPFAvailable() }

// EBPFHookConfig configures one eBPF-backed lifecycle hook.
type EBPFHookConfig struct {
	Point       Point  `json:"point"`
	Program     string `json:"program"`
	Runtime     string `json:"runtime,omitempty"`
	Mode        Mode   `json:"mode,omitempty"`
	Priority    int    `json:"priority,omitempty"`
	Timeout     string `json:"timeout,omitempty"`
	MaxParallel int    `json:"max_parallel,omitempty"`
}

// NewEBPFHook constructs an eBPF-backed Hook using the supplied runtime.
func NewEBPFHook(runtime EBPFRuntime, raw EBPFHookConfig) (Hook, error) {
	if runtime == nil {
		return Hook{}, errors.New("extension: eBPF runtime is required")
	}
	name := strings.TrimSpace(runtime.Name())
	if name == "" || len(name) > 64 || containsControl(name) {
		return Hook{}, errors.New("extension: invalid eBPF runtime name")
	}
	if configured := strings.TrimSpace(raw.Runtime); configured != "" && configured != name {
		return Hook{}, fmt.Errorf("extension: configured eBPF runtime %q does not match %q", configured, name)
	}
	program, err := normalizeEBPFProgramRef(raw.Program)
	if err != nil {
		return Hook{}, err
	}
	timeout, err := parseHookTimeout(raw.Timeout)
	if err != nil {
		return Hook{}, err
	}
	handler := ebpfHandler{runtime: runtime, program: program}
	return Hook{
		Point:       raw.Point,
		Priority:    raw.Priority,
		Mode:        raw.Mode,
		Timeout:     timeout,
		MaxParallel: raw.MaxParallel,
		Handler:     handler.run,
	}, nil
}

// RegisterEBPF atomically registers an eBPF-backed extension and marks the
// registry so the in-band API can advertise the runtime.
func (r *Registry) RegisterEBPF(definition Definition) error {
	if err := r.Register(definition); err != nil {
		return err
	}
	markRegistryRuntime(r, EBPFRuntimeKind)
	return nil
}

// HasRuntime reports whether a runtime kind is active in this registry.
func (r *Registry) HasRuntime(kind string) bool {
	if r == nil {
		return false
	}
	value, ok := registryRuntimes.Load(r)
	if !ok {
		return false
	}
	set := value.(*runtimeSet)
	set.mu.RLock()
	_, ok = set.values[strings.TrimSpace(kind)]
	set.mu.RUnlock()
	return ok
}

type runtimeSet struct {
	mu     sync.RWMutex
	values map[string]struct{}
}

var registryRuntimes sync.Map

func markRegistryRuntime(registry *Registry, kind string) {
	if registry == nil || strings.TrimSpace(kind) == "" {
		return
	}
	actual, _ := registryRuntimes.LoadOrStore(registry, &runtimeSet{values: map[string]struct{}{}})
	set := actual.(*runtimeSet)
	set.mu.Lock()
	set.values[strings.TrimSpace(kind)] = struct{}{}
	set.mu.Unlock()
}

type ebpfHandler struct {
	runtime EBPFRuntime
	program string
}

func (h ebpfHandler) run(ctx context.Context, event Event) error {
	input, err := MarshalEBPFEvent(event)
	if err != nil {
		return err
	}
	decision, err := h.runtime.Run(ctx, EBPFRuntimeRequest{Program: h.program, Input: input})
	if err != nil {
		return fmt.Errorf("eBPF runtime %s: %w", h.runtime.Name(), err)
	}
	if decision != EBPFDecisionAllow {
		return fmt.Errorf("eBPF program rejected event with decision %d", decision)
	}
	return nil
}

// MarshalEBPFEvent encodes a privacy-preserving, fixed-size event for an eBPF
// VM. Raw node names, session bindings, service metadata, and attributes are not
// included; only stable numeric fields and SHA-256 digests cross the VM boundary.
func MarshalEBPFEvent(raw Event) ([]byte, error) {
	event, err := normalizeEvent(raw)
	if err != nil {
		return nil, err
	}
	if event.OccurredAtUnixNano < 0 {
		return nil, errors.New("extension: invalid eBPF event timestamp")
	}
	point, err := ebpfPointCode(event.Point)
	if err != nil {
		return nil, err
	}
	payload := make([]byte, EBPFEventSize)
	copy(payload[ebpfOffsetMagic:ebpfOffsetMagic+4], ebpfEventMagic[:])
	binary.LittleEndian.PutUint16(payload[ebpfOffsetABIVersion:ebpfOffsetABIVersion+2], 1)
	binary.LittleEndian.PutUint16(payload[ebpfOffsetPoint:ebpfOffsetPoint+2], point)
	binary.LittleEndian.PutUint16(payload[ebpfOffsetServiceID:ebpfOffsetServiceID+2], event.ServiceID)
	flags := uint16(0)
	if event.MetadataSHA256 != "" || event.MetadataBytes > 0 {
		flags |= ebpfFlagMetadata
	}
	if len(event.Attributes) > 0 {
		flags |= ebpfFlagAttributes
	}
	binary.LittleEndian.PutUint16(payload[ebpfOffsetFlags:ebpfOffsetFlags+2], flags)
	binary.LittleEndian.PutUint32(payload[ebpfOffsetMetadataBytes:ebpfOffsetMetadataBytes+4], uint32(event.MetadataBytes))
	binary.LittleEndian.PutUint64(payload[ebpfOffsetOccurredAt:ebpfOffsetOccurredAt+8], uint64(event.OccurredAtUnixNano))
	putDigest(payload[ebpfOffsetSessionDigest:ebpfOffsetSessionDigest+32], event.SessionBinding)
	putDigest(payload[ebpfOffsetLocalDigest:ebpfOffsetLocalDigest+32], event.LocalNode)
	putDigest(payload[ebpfOffsetPeerDigest:ebpfOffsetPeerDigest+32], event.PeerNode)
	putDigest(payload[ebpfOffsetTargetDigest:ebpfOffsetTargetDigest+32], event.TargetNode)
	putDigest(payload[ebpfOffsetServiceDigest:ebpfOffsetServiceDigest+32], event.Service)
	if event.MetadataSHA256 != "" {
		digest, decodeErr := hex.DecodeString(event.MetadataSHA256)
		if decodeErr != nil || len(digest) != sha256.Size {
			return nil, errors.New("extension: invalid metadata digest")
		}
		copy(payload[ebpfOffsetMetadataDigest:ebpfOffsetMetadataDigest+32], digest)
	}
	attrsDigest := digestAttributes(event.Attributes)
	copy(payload[ebpfOffsetAttrsDigest:ebpfOffsetAttrsDigest+32], attrsDigest[:])
	return payload, nil
}

func normalizeEBPFProgramRef(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" || len(value) > maxEBPFProgramRef || containsControl(value) || strings.IndexByte(value, 0) >= 0 {
		return "", errors.New("extension: invalid eBPF program reference")
	}
	return value, nil
}

func ebpfPointCode(point Point) (uint16, error) {
	switch point {
	case PointSessionReady:
		return 1, nil
	case PointSessionClosed:
		return 2, nil
	case PointTargetOpened:
		return 3, nil
	case PointTargetAuthorized:
		return 4, nil
	case PointTargetForwarding:
		return 5, nil
	default:
		return 0, fmt.Errorf("extension: unsupported eBPF hook point %q", point)
	}
}

func putDigest(destination []byte, value string) {
	digest := sha256.Sum256([]byte(value))
	copy(destination, digest[:])
}

func digestAttributes(values map[string]string) [sha256.Size]byte {
	if len(values) == 0 {
		return sha256.Sum256(nil)
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	hash := sha256.New()
	var length [4]byte
	for _, key := range keys {
		binary.LittleEndian.PutUint32(length[:], uint32(len(key)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(key))
		value := values[key]
		binary.LittleEndian.PutUint32(length[:], uint32(len(value)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(value))
	}
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result
}
