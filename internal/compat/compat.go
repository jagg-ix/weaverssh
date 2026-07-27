// Package compat describes external protocol adapters that can be used around
// weaverssh without replacing the SSH/X11/WebSocket data plane.
package compat

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
)

const Version = "weaverssh.compat.v1"

const (
	KindS3     = "s3"
	KindHTTPS  = "https-tls"
	KindMQTT   = "mqtt"
	KindHadoop = "hadoop"
)

const DataPlaneOwnerWeaverssh = "weaverssh"

type Profile struct {
	Version  string            `json:"version"`
	Name     string            `json:"name"`
	Kind     string            `json:"kind"`
	Endpoint string            `json:"endpoint"`
	AuthRef  string            `json:"auth_ref,omitempty"`
	Region   string            `json:"region,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

type Plan struct {
	Version         string   `json:"version"`
	Name            string   `json:"name"`
	Kind            string   `json:"kind"`
	Endpoint        string   `json:"endpoint"`
	Scheme          string   `json:"scheme"`
	TLSRequired     bool     `json:"tls_required"`
	LoopbackOnly    bool     `json:"loopback_only,omitempty"`
	DataPlaneOwner  string   `json:"data_plane_owner"`
	Capabilities    []string `json:"capabilities"`
	RequiredEnv     []string `json:"required_env,omitempty"`
	ExampleCommands []string `json:"example_commands,omitempty"`
	Notes           []string `json:"notes,omitempty"`
}

func SupportedKinds() []string {
	return []string{KindS3, KindHTTPS, KindMQTT, KindHadoop}
}

func NormalizeKind(kind string) string {
	s := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(kind, "_", "-")))
	switch s {
	case "", KindS3, "object", "object-store", "s3-compatible", "minio":
		return KindS3
	case "https", "tls", "https-tls", "http-tls", "webhook", "rest":
		return KindHTTPS
	case "mqtt", "mqtts", "pubsub", "pub-sub":
		return KindMQTT
	case "hadoop", "hdfs", "webhdfs":
		return KindHadoop
	default:
		return s
	}
}

func KnownKind(kind string) bool {
	switch NormalizeKind(kind) {
	case KindS3, KindHTTPS, KindMQTT, KindHadoop:
		return true
	default:
		return false
	}
}

func (p Profile) Normalize() Profile {
	out := p
	out.Version = strings.TrimSpace(out.Version)
	if out.Version == "" {
		out.Version = Version
	}
	out.Kind = NormalizeKind(out.Kind)
	out.Name = strings.TrimSpace(out.Name)
	if out.Name == "" {
		out.Name = out.Kind
	}
	out.Endpoint = strings.TrimSpace(out.Endpoint)
	out.AuthRef = strings.TrimSpace(out.AuthRef)
	out.Region = strings.TrimSpace(out.Region)
	if len(out.Metadata) == 0 {
		out.Metadata = nil
	}
	return out
}

func (p Profile) Validate() error {
	p = p.Normalize()
	if p.Version != Version {
		return fmt.Errorf("unsupported compatibility profile version %q", p.Version)
	}
	if !KnownKind(p.Kind) {
		return fmt.Errorf("unsupported compatibility kind %q; supported kinds: %s", p.Kind, strings.Join(SupportedKinds(), ", "))
	}
	if p.Endpoint == "" {
		return fmt.Errorf("endpoint is required for %s compatibility", p.Kind)
	}
	u, err := parseEndpoint(p.Endpoint)
	if err != nil {
		return err
	}
	scheme := strings.ToLower(u.Scheme)
	switch p.Kind {
	case KindS3:
		if scheme != "s3" && scheme != "https" {
			return fmt.Errorf("s3 compatibility requires s3://bucket/prefix or https://s3-compatible-endpoint/bucket/prefix")
		}
		if scheme == "s3" && strings.TrimSpace(u.Host) == "" {
			return fmt.Errorf("s3:// endpoint requires a bucket name")
		}
	case KindHTTPS:
		if scheme != "https" {
			return fmt.Errorf("https-tls compatibility requires https:// endpoint")
		}
	case KindMQTT:
		if scheme != "mqtt" && scheme != "mqtts" {
			return fmt.Errorf("mqtt compatibility requires mqtt:// or mqtts:// endpoint")
		}
		if scheme == "mqtt" && !isLoopbackHost(u.Hostname()) {
			return fmt.Errorf("mqtt:// is accepted only for loopback brokers; use mqtts:// for non-loopback brokers")
		}
	case KindHadoop:
		if scheme != "hdfs" && scheme != "webhdfs" && scheme != "https" {
			return fmt.Errorf("hadoop compatibility requires hdfs://, webhdfs://, or https:// WebHDFS endpoint")
		}
		if scheme == "https" && strings.TrimSpace(u.Host) == "" {
			return fmt.Errorf("https Hadoop/WebHDFS endpoint requires a host")
		}
	}
	return nil
}

func (p Profile) Plan() (Plan, error) {
	p = p.Normalize()
	if err := p.Validate(); err != nil {
		return Plan{}, err
	}
	u, _ := parseEndpoint(p.Endpoint)
	plan := Plan{
		Version:        Version,
		Name:           p.Name,
		Kind:           p.Kind,
		Endpoint:       p.Endpoint,
		Scheme:         strings.ToLower(u.Scheme),
		DataPlaneOwner: DataPlaneOwnerWeaverssh,
	}
	switch p.Kind {
	case KindS3:
		plan.TLSRequired = true
		plan.Capabilities = []string{"object-store.pull", "object-store.push", "vfs.import-export"}
		plan.RequiredEnv = []string{"AWS_ACCESS_KEY_ID or compatible identity provider", "AWS_SECRET_ACCESS_KEY or compatible identity provider"}
		if p.Region != "" {
			plan.RequiredEnv = append(plan.RequiredEnv, "AWS_REGION="+p.Region)
		}
		plan.ExampleCommands = []string{
			"wv compat --kind s3 --endpoint " + p.Endpoint,
			"aws s3 cp <local-path> " + p.Endpoint + "  # external adapter; data remains policy-gated by wv workflow",
		}
		plan.Notes = []string{
			"S3 is treated as an object-store adapter for import/export workflows, not as the weaverssh tunnel.",
			"Use TLS-backed S3-compatible endpoints and never store access keys in a wv profile.",
		}
	case KindHTTPS:
		plan.TLSRequired = true
		plan.Capabilities = []string{"https.webhook", "https.artifact.fetch", "tls.endpoint.verify"}
		plan.RequiredEnv = []string{"system CA trust store or explicit pinned CA/certificate policy"}
		plan.ExampleCommands = []string{
			"wv compat https --endpoint " + p.Endpoint,
			"curl --proto '=https' --tlsv1.2 --fail " + p.Endpoint,
		}
		plan.Notes = []string{"HTTPS/TLS adapters are for control, artifact, or webhook edges and must terminate at an authorized weaverssh workflow."}
	case KindMQTT:
		plan.TLSRequired = plan.Scheme == "mqtts"
		plan.LoopbackOnly = plan.Scheme == "mqtt"
		plan.Capabilities = []string{"pubsub.publish", "pubsub.subscribe", "pubsub.mesh"}
		plan.RequiredEnv = []string{"WEAVERSSH_MQTT_BROKER=" + p.Endpoint}
		plan.ExampleCommands = []string{
			"WEAVERSSH_MQTT_BROKER=" + p.Endpoint + " wv pubsub status",
			"WEAVERSSH_MQTT_BROKER=" + p.Endpoint + " wv pubsub subscribe --topic weaverssh/# --limit 1",
		}
		plan.Notes = []string{
			"MQTT carries small events and audit/status records only; bulk bytes stay on weaverssh streams.",
			"Use mqtts:// outside loopback or an already protected SSH/weaverssh channel.",
		}
	case KindHadoop:
		plan.TLSRequired = plan.Scheme == "https"
		plan.Capabilities = []string{"hdfs.import-export", "webhdfs.adapter", "vfs.import-export"}
		plan.RequiredEnv = []string{"HADOOP_CONF_DIR or explicit WebHDFS endpoint", "Kerberos/token provider when the cluster requires it"}
		plan.ExampleCommands = []string{
			"wv compat hadoop --endpoint " + p.Endpoint,
			"hdfs dfs -ls " + p.Endpoint + "  # external adapter check; wv policy still gates workflow admission",
		}
		plan.Notes = []string{
			"Hadoop/HDFS is treated as a storage adapter for import/export workflows, not as a tunnel mechanism.",
			"Prefer WebHDFS over HTTPS or cluster-native Kerberos/TLS settings for production.",
		}
	}
	sort.Strings(plan.Capabilities)
	return plan, nil
}

func parseEndpoint(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("parse endpoint: %w", err)
	}
	if u.Scheme == "" {
		return nil, fmt.Errorf("endpoint requires a URI scheme")
	}
	return u, nil
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if host == "" {
		return false
	}
	lower := strings.ToLower(host)
	if lower == "localhost" || lower == "ip6-localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
