package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"weaverssh/internal/vfs"
)

type p9AdapterUseResult struct {
	OK          bool             `json:"ok"`
	ProfilePath string           `json:"profile_path"`
	ConfigPath  string           `json:"config_path"`
	Plan        vfs.ProviderPlan `json:"plan"`
	Config      vfs.Config       `json:"config"`
}

type p9AdapterStatus struct {
	OK       bool                `json:"ok"`
	Active   bool                `json:"active"`
	Endpoint string              `json:"endpoint,omitempty"`
	Socks    string              `json:"socks,omitempty"`
	Profile  vfs.ProviderProfile `json:"profile,omitempty"`
	Plan     vfs.ProviderPlan    `json:"plan,omitempty"`
	Reason   string              `json:"reason,omitempty"`
}

func cmd9PAdapter(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "plan":
			return cmd9PAdapterPlan(args[1:])
		case "use", "set", "save":
			return cmd9PAdapterUse(args[1:])
		case "status", "show":
			return cmd9PAdapterStatus(args[1:])
		case "help", "-h", "--help":
			print9PAdapterHelp()
			return 0
		}
		if !strings.HasPrefix(args[0], "-") {
			fmt.Fprintf(os.Stderr, "9p-adapter: unknown command %q\n", args[0])
			print9PAdapterHelp()
			return 2
		}
	}
	print9PAdapterHelp()
	return 2
}

func cmd9PAdapterPlan(args []string) int {
	fs, profileFlags, jsonOut := new9PAdapterFlagSet("9p-adapter plan")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv 9p-adapter plan --kind external-tcp-9p --endpoint HOST:PORT [--json]")
		fmt.Fprintln(os.Stderr, "       wv 9p-adapter plan --kind qemu-virtfs --source PATH --mount-tag TAG [--mount-point DIR] [--json]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	profile := profileFlags.profile()
	plan, err := profile.Plan()
	if err != nil {
		fmt.Fprintf(os.Stderr, "9p-adapter plan: %v\n", err)
		return 2
	}
	if *jsonOut {
		return printJSON(plan)
	}
	print9PAdapterPlan(plan)
	return 0
}

func cmd9PAdapterUse(args []string) int {
	fs, profileFlags, jsonOut := new9PAdapterFlagSet("9p-adapter use")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv 9p-adapter use --kind external-tcp-9p --endpoint HOST:PORT [--name NAME] [--json]")
		fmt.Fprintln(os.Stderr, "  Saves the provider and makes directly dialable providers active for vfs:// commands.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	profile := profileFlags.profile()
	plan, err := profile.Plan()
	if err != nil {
		fmt.Fprintf(os.Stderr, "9p-adapter use: %v\n", err)
		return 2
	}
	profilePath, err := vfs.SaveProviderProfile(profile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "9p-adapter use: save profile: %v\n", err)
		return 1
	}
	cfg, _ := vfs.LoadConfig()
	cfg.ProviderName = profile.Normalize().Name
	cfg.Provider = &plan.Profile
	if endpoint, socks, ok := plan.Profile.EndpointPair(); ok {
		cfg.Endpoint = endpoint
		cfg.Socks = socks
	}
	if err := vfs.SaveConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "9p-adapter use: save config: %v\n", err)
		return 1
	}
	result := p9AdapterUseResult{OK: true, ProfilePath: profilePath, ConfigPath: vfs.ConfigPath(), Plan: plan, Config: cfg}
	if *jsonOut {
		return printJSON(result)
	}
	fmt.Printf("saved provider: %s\n", profilePath)
	fmt.Printf("updated config:  %s\n", vfs.ConfigPath())
	print9PAdapterPlan(plan)
	if !plan.DirectlyDialable {
		fmt.Println("note: this provider is a launch/mount plan; it will not replace the active vfs:// TCP endpoint until exposed through a dialable adapter.")
	}
	return 0
}

func cmd9PAdapterStatus(args []string) int {
	fs := flag.NewFlagSet("9p-adapter status", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON")
	profileName := fs.String("profile", "", "provider name or JSON profile path to inspect")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv 9p-adapter status [--profile NAME|PATH] [--json]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	var profile vfs.ProviderProfile
	var active bool
	var err error
	if strings.TrimSpace(*profileName) != "" {
		profile, err = vfs.LoadProviderProfile(*profileName)
		active = err == nil
	} else {
		profile, active, err = vfs.ResolveProviderConfig()
	}
	if err != nil {
		status := p9AdapterStatus{OK: false, Active: false, Reason: err.Error()}
		if *jsonOut {
			return printJSON(status)
		}
		fmt.Fprintf(os.Stderr, "9p-adapter status: %v\n", err)
		return 1
	}
	if !active {
		endpoint, socks := vfs.Endpoint()
		status := p9AdapterStatus{OK: true, Active: false, Endpoint: endpoint, Socks: socks, Reason: "no provider profile configured; using default endpoint resolution"}
		if *jsonOut {
			return printJSON(status)
		}
		fmt.Println("provider: none")
		fmt.Printf("endpoint: %s\n", endpoint)
		if socks != "" {
			fmt.Printf("socks:    %s\n", socks)
		}
		return 0
	}
	plan, err := profile.Plan()
	if err != nil {
		status := p9AdapterStatus{OK: false, Active: true, Profile: profile, Reason: err.Error()}
		if *jsonOut {
			return printJSON(status)
		}
		fmt.Fprintf(os.Stderr, "9p-adapter status: %v\n", err)
		return 1
	}
	endpoint, socks := vfs.Endpoint()
	status := p9AdapterStatus{OK: true, Active: true, Endpoint: endpoint, Socks: socks, Profile: profile, Plan: plan}
	if *jsonOut {
		return printJSON(status)
	}
	fmt.Printf("provider: %s (%s)\n", profile.Name, profile.Kind)
	fmt.Printf("endpoint: %s\n", endpoint)
	if socks != "" {
		fmt.Printf("socks:    %s\n", socks)
	}
	print9PAdapterPlan(plan)
	return 0
}

type p9AdapterFlags struct {
	name          *string
	kind          *string
	endpoint      *string
	socks         *string
	source        *string
	mountTag      *string
	mountPoint    *string
	securityModel *string
	fsdevID       *string
	device        *string
	readWrite     *bool
	dialects      *string
}

func new9PAdapterFlagSet(name string) (*flag.FlagSet, p9AdapterFlags, *bool) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	flags := p9AdapterFlags{
		name:          fs.String("name", "default", "provider profile name"),
		kind:          fs.String("kind", vfs.ProviderExternalTCP9P, "provider kind: weaverssh-9p, external-tcp-9p, qemu-virtfs"),
		endpoint:      fs.String("endpoint", "", "9P TCP endpoint host:port for directly dialable providers"),
		socks:         fs.String("socks", "", "optional SOCKS5 host:port to reach endpoint"),
		source:        fs.String("source", "", "source directory for qemu-virtfs"),
		mountTag:      fs.String("mount-tag", "weaverssh", "QEMU virtio-9p mount tag"),
		mountPoint:    fs.String("mount-point", "/mnt/weaverssh", "guest mount point for qemu-virtfs"),
		securityModel: fs.String("security-model", "mapped-xattr", "QEMU 9P security model"),
		fsdevID:       fs.String("fsdev-id", "", "QEMU fsdev id; default derived from name"),
		device:        fs.String("device", "virtio-9p-pci", "QEMU 9P device model"),
		readWrite:     fs.Bool("rw", false, "allow writes where provider supports it; default is read-only"),
		dialects:      fs.String("dialects", "9P2000.L,9P2000.u,9P2000", "comma-separated preferred 9P dialects"),
	}
	jsonOut := fs.Bool("json", false, "emit JSON")
	return fs, flags, jsonOut
}

func (f p9AdapterFlags) profile() vfs.ProviderProfile {
	return vfs.ProviderProfile{
		Name:          *f.name,
		Kind:          *f.kind,
		Endpoint:      *f.endpoint,
		Socks:         *f.socks,
		ReadOnly:      !*f.readWrite,
		Dialects:      splitCSV(*f.dialects),
		SourcePath:    *f.source,
		MountTag:      *f.mountTag,
		MountPoint:    *f.mountPoint,
		SecurityModel: *f.securityModel,
		FSDevID:       *f.fsdevID,
		Device:        *f.device,
	}.Normalize()
}

func splitCSV(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func print9PAdapterPlan(plan vfs.ProviderPlan) {
	p := plan.Profile
	fmt.Printf("provider: %s (%s)\n", p.Name, p.Kind)
	fmt.Printf("dialable: %t\n", plan.DirectlyDialable)
	if plan.Endpoint != "" {
		fmt.Printf("endpoint: %s\n", plan.Endpoint)
	}
	if plan.Socks != "" {
		fmt.Printf("socks:    %s\n", plan.Socks)
	}
	if len(plan.QEMUArgs) > 0 {
		fmt.Printf("qemu args: %s\n", strings.Join(plan.QEMUArgs, " "))
	}
	if len(plan.GuestMountCommand) > 0 {
		fmt.Printf("guest mount: %s\n", strings.Join(plan.GuestMountCommand, " "))
	}
	for _, note := range plan.Notes {
		fmt.Printf("note: %s\n", note)
	}
}

func print9PAdapterHelp() {
	fmt.Print(`wv 9p-adapter - configure external 9P providers for vfs://

Usage:
  wv 9p-adapter plan --kind external-tcp-9p --endpoint HOST:PORT [--json]
  wv 9p-adapter plan --kind qemu-virtfs --source PATH --mount-tag TAG [--mount-point DIR]
  wv 9p-adapter use  --kind external-tcp-9p --endpoint HOST:PORT [--name NAME]
  wv 9p-adapter status [--profile NAME|PATH] [--json]

Provider kinds:
  weaverssh-9p      Repo-native or compatible wv-9p TCP endpoint.
  external-tcp-9p   Any directly dialable 9P TCP server exposed by another app.
  qemu-virtfs       QEMU -fsdev/-device virtio-9p launch and guest mount plan.

Notes:
  Direct TCP providers can back vfs:// immediately after 'use'. QEMU virtio-9p
  is visible inside the guest through a mount tag, so 'plan' prints QEMU args
  and guest mount commands instead of pretending QEMU is a host TCP endpoint.
`)
}
