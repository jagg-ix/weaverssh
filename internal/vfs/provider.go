package vfs

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

const (
	ProviderVersion = "weaverssh.vfs.provider.v1"

	ProviderWeaverssh9P   = "weaverssh-9p"
	ProviderExternalTCP9P = "external-tcp-9p"
	ProviderQEMUVirtFS    = "qemu-virtfs"

	EnvProviderConfig = "WEAVERSSH_VFS_PROVIDER"
	EnvProviderName   = "WEAVERSSH_VFS_PROVIDER_NAME"
)

var providerNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// ProviderProfile describes a 9P filesystem provider that can back the vfs://
// namespace. TCP providers are directly dialable by the p9client. QEMU virtfs
// providers are launch/mount plans because virtio-9p is exposed to the guest,
// not as a host-side TCP socket.
type ProviderProfile struct {
	Version       string            `json:"version"`
	Name          string            `json:"name"`
	Kind          string            `json:"kind"`
	Endpoint      string            `json:"endpoint,omitempty"`
	Socks         string            `json:"socks,omitempty"`
	ReadOnly      bool              `json:"read_only,omitempty"`
	Dialects      []string          `json:"dialects,omitempty"`
	SourcePath    string            `json:"source_path,omitempty"`
	MountTag      string            `json:"mount_tag,omitempty"`
	MountPoint    string            `json:"mount_point,omitempty"`
	SecurityModel string            `json:"security_model,omitempty"`
	FSDevID       string            `json:"fsdev_id,omitempty"`
	Device        string            `json:"device,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

type ProviderPlan struct {
	Profile           ProviderProfile `json:"profile"`
	DirectlyDialable  bool            `json:"directly_dialable"`
	Endpoint          string          `json:"endpoint,omitempty"`
	Socks             string          `json:"socks,omitempty"`
	QEMUArgs          []string        `json:"qemu_args,omitempty"`
	GuestMountCommand []string        `json:"guest_mount_command,omitempty"`
	Notes             []string        `json:"notes,omitempty"`
}

func (p ProviderProfile) Normalize() ProviderProfile {
	p.Version = strings.TrimSpace(p.Version)
	if p.Version == "" {
		p.Version = ProviderVersion
	}
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		p.Name = "default"
	}
	p.Kind = strings.TrimSpace(p.Kind)
	if p.Kind == "" {
		p.Kind = ProviderExternalTCP9P
	}
	p.Endpoint = strings.TrimSpace(p.Endpoint)
	p.Socks = strings.TrimSpace(p.Socks)
	p.SourcePath = strings.TrimSpace(p.SourcePath)
	p.MountTag = strings.TrimSpace(p.MountTag)
	if p.MountTag == "" && p.Kind == ProviderQEMUVirtFS {
		p.MountTag = "weaverssh"
	}
	p.MountPoint = strings.TrimSpace(p.MountPoint)
	if p.MountPoint == "" && p.Kind == ProviderQEMUVirtFS {
		p.MountPoint = "/mnt/weaverssh"
	}
	p.SecurityModel = strings.TrimSpace(p.SecurityModel)
	if p.SecurityModel == "" && p.Kind == ProviderQEMUVirtFS {
		p.SecurityModel = "mapped-xattr"
	}
	p.FSDevID = strings.TrimSpace(p.FSDevID)
	if p.FSDevID == "" && p.Kind == ProviderQEMUVirtFS {
		p.FSDevID = safeQEMUIdentifier(p.Name)
	}
	p.Device = strings.TrimSpace(p.Device)
	if p.Device == "" && p.Kind == ProviderQEMUVirtFS {
		p.Device = "virtio-9p-pci"
	}
	p.Dialects = cleanStrings(p.Dialects)
	if len(p.Dialects) == 0 {
		p.Dialects = []string{"9P2000.L", "9P2000.u", "9P2000"}
	}
	if len(p.Metadata) == 0 {
		p.Metadata = nil
	}
	return p
}

func (p ProviderProfile) Validate() error {
	p = p.Normalize()
	if p.Version != ProviderVersion {
		return fmt.Errorf("unsupported provider version %q", p.Version)
	}
	if !providerNamePattern.MatchString(p.Name) {
		return fmt.Errorf("provider name %q is not safe", p.Name)
	}
	switch p.Kind {
	case ProviderWeaverssh9P, ProviderExternalTCP9P:
		if p.Endpoint == "" {
			return fmt.Errorf("endpoint is required for %s", p.Kind)
		}
		if err := validateHostPort(p.Endpoint); err != nil {
			return fmt.Errorf("endpoint: %w", err)
		}
		if p.Socks != "" {
			if err := validateHostPort(p.Socks); err != nil {
				return fmt.Errorf("socks: %w", err)
			}
		}
	case ProviderQEMUVirtFS:
		if p.SourcePath == "" {
			return fmt.Errorf("source path is required for qemu-virtfs")
		}
		if p.MountTag == "" {
			return fmt.Errorf("mount tag is required for qemu-virtfs")
		}
		if strings.ContainsAny(p.MountTag, "/\\ \t\n") {
			return fmt.Errorf("mount tag %q is not safe", p.MountTag)
		}
		if p.FSDevID == "" || strings.ContainsAny(p.FSDevID, "/\\,= \t\n") {
			return fmt.Errorf("fsdev id %q is not safe", p.FSDevID)
		}
		if p.SecurityModel == "" {
			return fmt.Errorf("security model is required for qemu-virtfs")
		}
	default:
		return fmt.Errorf("unsupported provider kind %q", p.Kind)
	}
	return nil
}

func (p ProviderProfile) Plan() (ProviderPlan, error) {
	p = p.Normalize()
	if err := p.Validate(); err != nil {
		return ProviderPlan{}, err
	}
	plan := ProviderPlan{Profile: p}
	switch p.Kind {
	case ProviderWeaverssh9P, ProviderExternalTCP9P:
		plan.DirectlyDialable = true
		plan.Endpoint = p.Endpoint
		plan.Socks = p.Socks
		plan.Notes = append(plan.Notes, "This provider can back vfs:// directly through the p9client.")
	case ProviderQEMUVirtFS:
		plan.DirectlyDialable = false
		plan.QEMUArgs = p.QEMUArgs()
		plan.GuestMountCommand = p.GuestMountCommand()
		plan.Notes = append(plan.Notes,
			"QEMU virtio-9p is visible inside the guest through the mount tag; it is not a host-side TCP endpoint.",
			"Run the QEMU arguments when launching the VM, then run the guest mount command inside the VM.",
		)
	}
	return plan, nil
}

func (p ProviderProfile) QEMUArgs() []string {
	p = p.Normalize()
	if p.Kind != ProviderQEMUVirtFS {
		return nil
	}
	fsdev := fmt.Sprintf("local,id=%s,path=%s,security_model=%s", p.FSDevID, p.SourcePath, p.SecurityModel)
	if p.ReadOnly {
		fsdev += ",readonly=on"
	}
	device := fmt.Sprintf("%s,fsdev=%s,mount_tag=%s", p.Device, p.FSDevID, p.MountTag)
	return []string{"-fsdev", fsdev, "-device", device}
}

func (p ProviderProfile) GuestMountCommand() []string {
	p = p.Normalize()
	if p.Kind != ProviderQEMUVirtFS {
		return nil
	}
	opts := "trans=virtio,version=9p2000.L"
	if p.ReadOnly {
		opts += ",ro"
	}
	return []string{"mount", "-t", "9p", "-o", opts, p.MountTag, p.MountPoint}
}

func (p ProviderProfile) EndpointPair() (endpoint, socks string, ok bool) {
	p = p.Normalize()
	switch p.Kind {
	case ProviderWeaverssh9P, ProviderExternalTCP9P:
		return p.Endpoint, p.Socks, p.Endpoint != ""
	default:
		return "", "", false
	}
}

func SaveProviderProfile(profile ProviderProfile) (string, error) {
	profile = profile.Normalize()
	if err := profile.Validate(); err != nil {
		return "", err
	}
	path := ProviderProfilePath(profile.Name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return "", err
	}
	return path, os.WriteFile(path, append(data, '\n'), 0o644)
}

func LoadProviderProfile(nameOrPath string) (ProviderProfile, error) {
	path := strings.TrimSpace(nameOrPath)
	if path == "" {
		path = ActiveProviderName()
	}
	if path == "" {
		return ProviderProfile{}, fmt.Errorf("provider name or path is required")
	}
	if !strings.ContainsAny(path, `/\\`) && !strings.HasSuffix(path, ".json") {
		path = ProviderProfilePath(path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ProviderProfile{}, err
	}
	var profile ProviderProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		return ProviderProfile{}, err
	}
	profile = profile.Normalize()
	return profile, profile.Validate()
}

func ProviderProfilePath(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "default"
	}
	return filepath.Join(providerConfigDir(), "providers", name+".json")
}

func ActiveProviderName() string {
	return strings.TrimSpace(os.Getenv(EnvProviderName))
}

func ResolveProviderConfig() (ProviderProfile, bool, error) {
	if path := strings.TrimSpace(os.Getenv(EnvProviderConfig)); path != "" {
		profile, err := LoadProviderProfile(path)
		return profile, err == nil, err
	}
	if name := ActiveProviderName(); name != "" {
		profile, err := LoadProviderProfile(name)
		return profile, err == nil, err
	}
	cfg, err := LoadConfig()
	if err != nil {
		return ProviderProfile{}, false, nil
	}
	if cfg.Provider != nil {
		profile := cfg.Provider.Normalize()
		return profile, true, profile.Validate()
	}
	if cfg.ProviderName != "" {
		profile, err := LoadProviderProfile(cfg.ProviderName)
		return profile, err == nil, err
	}
	if cfg.Endpoint != "" {
		profile := ProviderProfile{Name: "config", Kind: ProviderExternalTCP9P, Endpoint: cfg.Endpoint, Socks: cfg.Socks}.Normalize()
		return profile, true, profile.Validate()
	}
	return ProviderProfile{}, false, nil
}

func providerConfigDir() string {
	if p := strings.TrimSpace(os.Getenv("WEAVERSSH_VFS_CONFIG_DIR")); p != "" {
		return p
	}
	var base string
	switch runtime.GOOS {
	case "windows":
		base = os.Getenv("APPDATA")
		if base == "" {
			base, _ = os.UserConfigDir()
		}
	default:
		if xdg := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); xdg != "" {
			base = xdg
		} else if home, err := os.UserHomeDir(); err == nil {
			base = filepath.Join(home, ".config")
		}
	}
	if base == "" {
		base = "."
	}
	return filepath.Join(base, "weaverssh", "vfs")
}

func validateHostPort(value string) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return err
	}
	if strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" {
		return fmt.Errorf("host and port are required")
	}
	return nil
}

func cleanStrings(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func safeQEMUIdentifier(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "weaverssh"
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '_' || r == '-' || r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), "._-")
	if out == "" {
		out = "weaverssh"
	}
	return out
}
