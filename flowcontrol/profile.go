package flowcontrol

import (
	"errors"
	"fmt"
	"math"
	"net"
	"sort"
	"strings"
	"time"
)

const (
	ContractVersion = "weaverssh.flowcontrol.v1"

	ProfileRealtime = "realtime"
	ProfileBalanced = "balanced"
	ProfileBulk     = "bulk"

	DefaultRTT = 40 * time.Millisecond
)

// Profile is the runtime contract that keeps the SSH-carried socket, the
// WebSocket framing layer, and the relay pump aligned. Values are bytes unless
// the name says otherwise.
type Profile struct {
	Name                      string `json:"name"`
	SSHSocketBufferBytes      int    `json:"ssh_socket_buffer_bytes"`
	X11PacketMaxBytes         int    `json:"x11_packet_max_bytes"`
	WebSocketReadBufferBytes  int    `json:"websocket_read_buffer_bytes"`
	WebSocketWriteBufferBytes int    `json:"websocket_write_buffer_bytes"`
	WebSocketFrameBytes       int    `json:"websocket_frame_bytes"`
	RelayReadBytes            int    `json:"relay_read_bytes"`
	QueueDepth                int    `json:"queue_depth"`
	TCPNoDelay                bool   `json:"tcp_no_delay"`
	WebSocketCompression      bool   `json:"websocket_compression"`
}

// Plan explains the resolved profile and the derived benchmark/capacity values.
type Plan struct {
	Version                  string   `json:"version"`
	Profile                  Profile  `json:"profile"`
	Matched                  bool     `json:"matched"`
	MismatchReasons          []string `json:"mismatch_reasons,omitempty"`
	BDPBytes                 int64    `json:"bdp_bytes"`
	RecommendedQueueDepth    int      `json:"recommended_queue_depth"`
	InFlightCapacityBytes    int64    `json:"in_flight_capacity_bytes"`
	EstimatedDrainTimeMillis int64    `json:"estimated_drain_time_ms"`
	BenchmarkPayloadBytes    []int    `json:"benchmark_payload_bytes"`
	BenchmarkCommands        []string `json:"benchmark_commands"`
	Warnings                 []string `json:"warnings,omitempty"`
}

var profiles = map[string]Profile{
	ProfileRealtime: {
		Name:                      ProfileRealtime,
		SSHSocketBufferBytes:      64 * 1024,
		X11PacketMaxBytes:         16 * 1024,
		WebSocketReadBufferBytes:  16 * 1024,
		WebSocketWriteBufferBytes: 16 * 1024,
		WebSocketFrameBytes:       16 * 1024,
		RelayReadBytes:            16 * 1024,
		QueueDepth:                4,
		TCPNoDelay:                true,
		WebSocketCompression:      false,
	},
	ProfileBalanced: {
		Name:                      ProfileBalanced,
		SSHSocketBufferBytes:      256 * 1024,
		X11PacketMaxBytes:         32 * 1024,
		WebSocketReadBufferBytes:  32 * 1024,
		WebSocketWriteBufferBytes: 32 * 1024,
		WebSocketFrameBytes:       32 * 1024,
		RelayReadBytes:            32 * 1024,
		QueueDepth:                8,
		TCPNoDelay:                true,
		WebSocketCompression:      false,
	},
	ProfileBulk: {
		Name:                      ProfileBulk,
		SSHSocketBufferBytes:      1024 * 1024,
		X11PacketMaxBytes:         64 * 1024,
		WebSocketReadBufferBytes:  64 * 1024,
		WebSocketWriteBufferBytes: 64 * 1024,
		WebSocketFrameBytes:       64 * 1024,
		RelayReadBytes:            64 * 1024,
		QueueDepth:                16,
		TCPNoDelay:                false,
		WebSocketCompression:      false,
	},
}

// Names returns all built-in profile names in stable order.
func Names() []string {
	names := make([]string, 0, len(profiles))
	for name := range profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// DefaultProfile returns the balanced profile used by runtime call sites that
// do not expose an operator-selected profile yet.
func DefaultProfile() Profile {
	p, _ := Builtin(ProfileBalanced)
	return p
}

// Builtin returns a normalized built-in profile.
func Builtin(name string) (Profile, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || name == "default" {
		name = ProfileBalanced
	}
	p, ok := profiles[name]
	if !ok {
		return Profile{}, fmt.Errorf("unsupported flow profile %q", name)
	}
	return p.Normalized(), nil
}

// Normalized returns a profile with safe defaults for unset or invalid fields.
func (p Profile) Normalized() Profile {
	if strings.TrimSpace(p.Name) == "" {
		p.Name = ProfileBalanced
	}
	if p.SSHSocketBufferBytes <= 0 {
		p.SSHSocketBufferBytes = 256 * 1024
	}
	if p.X11PacketMaxBytes <= 0 {
		p.X11PacketMaxBytes = 32 * 1024
	}
	if p.WebSocketFrameBytes <= 0 {
		p.WebSocketFrameBytes = minPositive(p.X11PacketMaxBytes, 32*1024)
	}
	if p.RelayReadBytes <= 0 {
		p.RelayReadBytes = p.WebSocketFrameBytes
	}
	if p.WebSocketReadBufferBytes <= 0 {
		p.WebSocketReadBufferBytes = p.WebSocketFrameBytes
	}
	if p.WebSocketWriteBufferBytes <= 0 {
		p.WebSocketWriteBufferBytes = p.WebSocketFrameBytes
	}
	if p.QueueDepth <= 0 {
		p.QueueDepth = 8
	}
	return p
}

// Validate returns a mismatch list instead of failing so operators can inspect
// an unsafe or poor profile and decide what to change.
func (p Profile) Validate() []string {
	p = p.Normalized()
	var reasons []string
	if p.WebSocketCompression {
		reasons = append(reasons, "websocket compression must be disabled for predictable buffering")
	}
	if p.WebSocketFrameBytes > p.X11PacketMaxBytes {
		reasons = append(reasons, "websocket frame payload exceeds X11 packet boundary")
	}
	if p.RelayReadBytes != p.WebSocketFrameBytes {
		reasons = append(reasons, "relay read chunk must match websocket frame payload")
	}
	if p.WebSocketReadBufferBytes < p.WebSocketFrameBytes {
		reasons = append(reasons, "websocket read buffer is smaller than websocket frame payload")
	}
	if p.WebSocketWriteBufferBytes < p.WebSocketFrameBytes {
		reasons = append(reasons, "websocket write buffer is smaller than websocket frame payload")
	}
	if p.SSHSocketBufferBytes < p.WebSocketFrameBytes*p.QueueDepth {
		reasons = append(reasons, "ssh socket buffer is smaller than websocket frame multiplied by queue depth")
	}
	return reasons
}

// BuildPlan computes capacity and benchmark guidance for a profile.
func BuildPlan(profile string, bandwidthMbps float64, rtt time.Duration) (Plan, error) {
	p, err := Builtin(profile)
	if err != nil {
		return Plan{}, err
	}
	if bandwidthMbps <= 0 {
		bandwidthMbps = 100
	}
	if rtt <= 0 {
		rtt = DefaultRTT
	}
	mismatches := p.Validate()
	bdpBytes := int64(math.Ceil((bandwidthMbps * 1000 * 1000 / 8) * rtt.Seconds()))
	recommendedQueue := int(math.Ceil(float64(bdpBytes) / float64(p.WebSocketFrameBytes)))
	if recommendedQueue < 1 {
		recommendedQueue = 1
	}
	capacity := int64(p.WebSocketFrameBytes * p.QueueDepth)
	drainMs := int64(0)
	if bandwidthMbps > 0 {
		drainMs = int64(math.Ceil((float64(capacity) * 8 / (bandwidthMbps * 1000 * 1000)) * 1000))
	}
	warnings := append([]string{}, mismatches...)
	if p.QueueDepth < recommendedQueue {
		warnings = append(warnings, fmt.Sprintf("queue depth %d is below BDP recommendation %d for %.2f Mbps and %s RTT", p.QueueDepth, recommendedQueue, bandwidthMbps, rtt))
	}
	return Plan{
		Version:                  ContractVersion,
		Profile:                  p,
		Matched:                  len(mismatches) == 0,
		MismatchReasons:          mismatches,
		BDPBytes:                 bdpBytes,
		RecommendedQueueDepth:    recommendedQueue,
		InFlightCapacityBytes:    capacity,
		EstimatedDrainTimeMillis: drainMs,
		BenchmarkPayloadBytes: []int{
			maxInt(1, p.WebSocketFrameBytes/4),
			p.WebSocketFrameBytes,
			p.WebSocketFrameBytes * p.QueueDepth,
		},
		BenchmarkCommands: []string{
			fmt.Sprintf("wv flow plan --profile %s --bandwidth-mbps %.0f --rtt %s", p.Name, bandwidthMbps, rtt),
			fmt.Sprintf("wv flow validate --profile %s", p.Name),
			fmt.Sprintf("wv instrument plan --provider ebpf --profile socket --chain origin,node1,node2"),
		},
		Warnings: warnings,
	}, nil
}

// ApplySocketOptions disables Nagle where the active profile requires latency
// over aggregation. Non-TCP connections are ignored.
func ApplySocketOptions(conn any, p Profile) error {
	if conn == nil {
		return nil
	}
	if !p.Normalized().TCPNoDelay {
		return nil
	}
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return nil
	}
	return tcp.SetNoDelay(true)
}

func minPositive(a, b int) int {
	if a <= 0 && b <= 0 {
		return 0
	}
	if a <= 0 {
		return b
	}
	if b <= 0 {
		return a
	}
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func ParseDurationText(value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return DefaultRTT, nil
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, err
	}
	if d <= 0 {
		return 0, errors.New("duration must be positive")
	}
	return d, nil
}
