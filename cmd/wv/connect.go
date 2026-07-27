package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// This file lets wv consume the weaverssh-service-dock connection wizard's
// autodetection (`connection-wizard-scan`) over a JSON contract: wv shells out
// to the dock binary and parses the scan, so SSH identity / host / profile
// discovery is shared with the dock rather than reimplemented here.

// ConnProfile mirrors the dock's ConnectionProfile (only the fields wv uses).
type ConnProfile struct {
	Name               string            `json:"name"`
	Version            string            `json:"version,omitempty"`
	Description        string            `json:"description,omitempty"`
	SSHHost            string            `json:"ssh_host,omitempty"`
	SSHUser            string            `json:"ssh_user,omitempty"`
	SSHPort            int               `json:"ssh_port,omitempty"`
	IdentityFile       string            `json:"identity_file,omitempty"`
	RepoRoot           string            `json:"repo_root,omitempty"`
	Adapter            string            `json:"adapter,omitempty"`
	CredentialProvider string            `json:"credential_provider,omitempty"`
	NinePPort          int               `json:"ninep_port,omitempty"`
	Tags               []string          `json:"tags,omitempty"`
	Labels             map[string]string `json:"labels,omitempty"`
	Capabilities       []ConnCapability  `json:"capabilities,omitempty"`
}

// ConnCapability is a native capability advertised by a connection profile
// version. This is descriptive metadata; operation authorization still happens
// through the runtime proof/policy layers.
type ConnCapability struct {
	ID          string `json:"id"`
	Description string `json:"description,omitempty"`
	Native      bool   `json:"native"`
	Since       string `json:"since,omitempty"`
}

// CredChoice is one autodetected credential option (ssh-agent, keychain, key file).
type CredChoice struct {
	Index  int    `json:"index"`
	Kind   string `json:"kind"`
	ID     string `json:"id"`
	Label  string `json:"label"`
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
	Path   string `json:"path,omitempty"`
	Source string `json:"source,omitempty"`
}

// SSHConfigSource is a discovered ssh_config file (with Include resolution).
type SSHConfigSource struct {
	Index  int    `json:"index"`
	Path   string `json:"path"`
	Scope  string `json:"scope"`
	Reason string `json:"reason"`
	Exists bool   `json:"exists"`
}

// Assessment is the wizard's readiness summary for the selected profile.
type Assessment struct {
	OK                 bool     `json:"ok"`
	State              string   `json:"state"`
	Summary            string   `json:"summary"`
	NextAction         string   `json:"next_action"`
	CredentialProvider string   `json:"credential_provider"`
	IdentityFile       string   `json:"identity_file"`
	IdentityFiles      []string `json:"identity_files"`
	SSHConfigs         []string `json:"ssh_configs"`
	Missing            []string `json:"missing"`
}

// Scan is the subset of `connection-wizard-scan -format json` wv consumes.
type Scan struct {
	OK                bool              `json:"ok"`
	Source            string            `json:"source"`
	Profile           ConnProfile       `json:"profile"`
	SelectedProfile   ConnProfile       `json:"selected_profile"`
	CredentialChoices []CredChoice      `json:"credential_choices"`
	Assessment        Assessment        `json:"assessment"`
	SSHConfigSources  []SSHConfigSource `json:"ssh_config_sources"`
	ConfigDir         string            `json:"config_dir"`
	ProfilesDir       string            `json:"profiles_dir"`
	StorePath         string            `json:"store_path"`
	// DiscoveredProfiles lists every connection the scanner proposed (from
	// ssh_config, PuTTY, and known_hosts). The native scanner fills this; the
	// external dock scanner may leave it empty.
	DiscoveredProfiles []ConnProfile `json:"discovered_profiles,omitempty"`
}

// ConnStore is wv's local profile store. It is intentionally separate from the
// scanner result: scans discover local facts; this store records the user's
// chosen reusable connections.
type ConnStore struct {
	Active      string        `json:"active,omitempty"`
	ActiveChain string        `json:"active_chain,omitempty"`
	Profiles    []ConnProfile `json:"profiles"`
	Chains      []ConnChain   `json:"chains,omitempty"`
	// Groups are pre-authorized candidate sets. A chain step "group:NAME" is
	// resolved at path-construction time to one member of group NAME, so a hop
	// can be chosen by lookup/alias without leaving the signed set.
	Groups []ConnGroup `json:"groups,omitempty"`
}

const (
	connVersionV1     = "weaverssh.connection.v1"
	connVersionV2     = "weaverssh.connection.v2"
	connLatestVersion = connVersionV2
	connLegacyVersion = connVersionV1
)

// ConnVersionSpec is the plug-in point for connection profile versions. New
// versions register their native capability set here; migrations use the same
// registry so docs, JSON output, and upgrade/downgrade behavior agree.
type ConnVersionSpec struct {
	Version      string           `json:"version"`
	Description  string           `json:"description"`
	Capabilities []ConnCapability `json:"capabilities"`
}

var (
	connVersionSpecs = map[string]ConnVersionSpec{}
	connVersionOrder []string
)

func init() {
	mustRegisterConnVersion(ConnVersionSpec{
		Version:     connVersionV1,
		Description: "legacy SSH profile shape: host/user/identity plus VFS endpoint metadata",
		Capabilities: []ConnCapability{
			{ID: "ssh.open", Description: "open an SSH client session to the profile host", Native: true, Since: connVersionV1},
			{ID: "ssh.identity.local", Description: "reference local SSH identity material or an agent", Native: true, Since: connVersionV1},
			{ID: "vfs.9p.endpoint", Description: "carry a 9P/VFS endpoint port for vfs:// operations", Native: true, Since: connVersionV1},
			{ID: "profile.activate", Description: "mark the profile as the active local connection", Native: true, Since: connVersionV1},
		},
	})
	mustRegisterConnVersion(ConnVersionSpec{
		Version:     connVersionV2,
		Description: "current profile shape: explicit capability report for mounts, SSHFS, install, and automation",
		Capabilities: []ConnCapability{
			{ID: "ssh.open", Description: "open an SSH client session to the profile host", Native: true, Since: connVersionV1},
			{ID: "ssh.identity.local", Description: "reference local SSH identity material or an agent", Native: true, Since: connVersionV1},
			{ID: "vfs.9p.endpoint", Description: "carry a 9P/VFS endpoint port for vfs:// operations", Native: true, Since: connVersionV1},
			{ID: "profile.activate", Description: "mark the profile as the active local connection", Native: true, Since: connVersionV1},
			{ID: "mount.fuse.status", Description: "report libfuse/macFUSE readiness before mounting", Native: true, Since: connVersionV2},
			{ID: "mount.sshfs", Description: "route sshfs through the selected weaverssh connection", Native: true, Since: connVersionV2},
			{ID: "remote.install", Description: "install wv on the remote host using the selected profile", Native: true, Since: connVersionV2},
			{ID: "connection.capability.report", Description: "emit native capability information for automation", Native: true, Since: connVersionV2},
		},
	})
}

func mustRegisterConnVersion(spec ConnVersionSpec) {
	if err := registerConnVersion(spec); err != nil {
		panic(err)
	}
}

func registerConnVersion(spec ConnVersionSpec) error {
	spec.Version = strings.TrimSpace(spec.Version)
	if spec.Version == "" {
		return fmt.Errorf("connection version cannot be empty")
	}
	if len(spec.Capabilities) == 0 {
		return fmt.Errorf("connection version %s has no capabilities", spec.Version)
	}
	if _, exists := connVersionSpecs[spec.Version]; !exists {
		connVersionOrder = append(connVersionOrder, spec.Version)
	}
	spec.Capabilities = dedupeCapabilities(spec.Capabilities)
	connVersionSpecs[spec.Version] = spec
	return nil
}

func dedupeCapabilities(caps []ConnCapability) []ConnCapability {
	seen := map[string]bool{}
	out := make([]ConnCapability, 0, len(caps))
	for _, cap := range caps {
		cap.ID = strings.TrimSpace(cap.ID)
		if cap.ID == "" || seen[cap.ID] {
			continue
		}
		seen[cap.ID] = true
		out = append(out, cap)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func connectionVersionSpec(version string) (ConnVersionSpec, bool) {
	spec, ok := connVersionSpecs[version]
	return spec, ok
}

func supportedConnectionVersions() []string {
	out := append([]string(nil), connVersionOrder...)
	sort.SliceStable(out, func(i, j int) bool {
		return connectionVersionIndex(out[i]) < connectionVersionIndex(out[j])
	})
	return out
}

func connectionVersionIndex(version string) int {
	for i, v := range connVersionOrder {
		if v == version {
			return i
		}
	}
	return -1
}

func profileVersion(p ConnProfile) string {
	if strings.TrimSpace(p.Version) != "" {
		return p.Version
	}
	return connLegacyVersion
}

func capabilitiesForVersion(version string) []ConnCapability {
	spec, ok := connectionVersionSpec(version)
	if !ok {
		return nil
	}
	return append([]ConnCapability(nil), spec.Capabilities...)
}

func connectionsStorePath() string {
	if p := strings.TrimSpace(os.Getenv("WEAVERSSH_CONNECTIONS_FILE")); p != "" {
		return p
	}
	// A project-local .wv directory keeps connection paths next to the code.
	if cfg := loadWVConfig(); strings.TrimSpace(cfg.ConnectionsFile) != "" {
		return cfg.ConnectionsFile
	}
	if dir := findWVDir(); dir != "" {
		return filepath.Join(dir, "connections.json")
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
	return filepath.Join(base, "weaverssh", "connections.json")
}

func loadConnStore() (ConnStore, error) {
	path := connectionsStorePath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ConnStore{}, nil
		}
		return ConnStore{}, err
	}
	if strings.TrimSpace(string(data)) == "" {
		return ConnStore{}, nil
	}
	var store ConnStore
	if err := json.Unmarshal(data, &store); err != nil {
		return ConnStore{}, fmt.Errorf("parse %s: %w", path, err)
	}
	sortProfiles(store.Profiles)
	sortChains(store.Chains)
	return store, nil
}

func saveConnStore(store ConnStore) error {
	sortProfiles(store.Profiles)
	sortChains(store.Chains)
	path := connectionsStorePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

func sortProfiles(profiles []ConnProfile) {
	sort.Slice(profiles, func(i, j int) bool {
		return profiles[i].Name < profiles[j].Name
	})
}

func findProfile(store ConnStore, name string) (ConnProfile, int, bool) {
	for i, p := range store.Profiles {
		if p.Name == name {
			return p, i, true
		}
	}
	return ConnProfile{}, -1, false
}

func upsertProfile(store ConnStore, profile ConnProfile) ConnStore {
	if _, i, ok := findProfile(store, profile.Name); ok {
		store.Profiles[i] = profile
		return store
	}
	store.Profiles = append(store.Profiles, profile)
	return store
}

func activeOrNamedProfile(store ConnStore, name string) (ConnProfile, error) {
	if strings.TrimSpace(name) == "" {
		name = store.Active
	}
	if strings.TrimSpace(name) == "" {
		return ConnProfile{}, fmt.Errorf("no active connection profile; run `wv connections use NAME`")
	}
	p, _, ok := findProfile(store, name)
	if !ok {
		return ConnProfile{}, fmt.Errorf("connection profile %q not found", name)
	}
	return p, nil
}

// parseScan decodes the wizard scan JSON.
func parseScan(b []byte) (*Scan, error) {
	var s Scan
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("parse wizard scan json: %w", err)
	}
	return &s, nil
}

func isExec(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir() && st.Mode()&0o111 != 0
}

// repoRoot walks up from the cwd to the weaverssh checkout (go.mod).
func repoRoot() (string, bool) {
	dir, err := os.Getwd()
	if err != nil {
		return "", false
	}
	for {
		if st, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil && !st.IsDir() {
			return dir, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

func repoRootOrCwd() string {
	if r, ok := repoRoot(); ok {
		return r
	}
	if d, err := os.Getwd(); err == nil {
		return d
	}
	return "."
}

// rawWizardScan returns the connection scan as JSON. By default this is the
// native scanner (connectionscan.Discover); an external dock scanner is used
// only when WEAVERSSH_CONNECTION_SCAN_BIN or WEAVERSSH_SERVICE_DOCK_BIN points
// at one, which lets the full service-dock wizard override the built-in scan.
func rawWizardScan(sshConfigSpec string) ([]byte, error) {
	if bin, prefix, ok := externalScanner(); ok {
		args := append(append([]string{}, prefix...), "-format", "json")
		cmd := exec.Command(bin, args...)
		cmd.Env = append(os.Environ(), "WEAVERSSH_REPO_ROOT="+repoRootOrCwd())
		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("connection scan: %w", err)
		}
		return out, nil
	}
	scan, err := nativeScan(sshConfigSpec)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(scan, "", "  ")
}

// runWizardScan returns the parsed connection scan.
func runWizardScan(sshConfigSpec string) (*Scan, error) {
	if _, _, ok := externalScanner(); ok {
		out, err := rawWizardScan(sshConfigSpec)
		if err != nil {
			return nil, err
		}
		return parseScan(out)
	}
	return nativeScan(sshConfigSpec)
}

// externalScanner returns a dock scanner binary only when one is explicitly
// configured. Unlike scanCommand it does not probe $PATH or sibling checkouts,
// so the native scanner stays the default for a standalone wv install.
func externalScanner() (bin string, prefix []string, ok bool) {
	if p := os.Getenv("WEAVERSSH_CONNECTION_SCAN_BIN"); p != "" && isExec(p) {
		return p, nil, true
	}
	if p := os.Getenv("WEAVERSSH_SERVICE_DOCK_BIN"); p != "" && isExec(p) {
		return p, []string{"connection-wizard-scan"}, true
	}
	return "", nil, false
}

// cmdConnections surfaces the dock wizard's autodetection through wv.
func cmdConnections(args []string) int {
	if len(args) > 0 {
		if strings.HasPrefix(args[0], "-") && connectionsArgsDefineNodes(args) {
			return cmdConnectionsNodes(args)
		}
		switch args[0] {
		case "scan":
			return cmdConnectionsScan(args[1:])
		case "list", "ls":
			return cmdConnectionsList(args[1:])
		case "set", "configure", "config":
			return cmdConnectionsSet(args[1:])
		case "use", "select":
			return cmdConnectionsUse(args[1:])
		case "show", "get":
			return cmdConnectionsShow(args[1:])
		case "current":
			return cmdConnectionsCurrent(args[1:])
		case "capabilities", "caps":
			return cmdConnectionsCapabilities(args[1:])
		case "upgrade":
			return cmdConnectionsMigrate(args[1:], true)
		case "downgrade":
			return cmdConnectionsMigrate(args[1:], false)
		case "help", "-h", "--help":
			printConnectionsHelp()
			return 0
		}
		if !strings.HasPrefix(args[0], "-") {
			fmt.Fprintf(os.Stderr, "connections: unknown command %q\n", args[0])
			printConnectionsHelp()
			return 2
		}
	}
	return cmdConnectionsScan(args)
}

func cmdConnectionsScan(args []string) int {
	fs := flag.NewFlagSet("connections", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit the raw connection scan JSON")
	importFlag := fs.Bool("import", false, "add discovered profiles to the connection store")
	sshConfig := fs.String("ssh-config", "", "ssh_config source: path, -, fd:N, pipe:PATH, or exec:CMD (default: ~/.ssh discovery, or .wv config)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv connections scan [--json] [--import] [--ssh-config SPEC]")
		fmt.Fprintln(os.Stderr, "  Autodetects SSH connection profiles from ~/.ssh/config, PuTTY saved sessions,")
		fmt.Fprintln(os.Stderr, "  and known_hosts. --import records the discovered profiles in the store.")
		fmt.Fprintln(os.Stderr, "  --ssh-config takes the config from a path, stdin (-), an fd (fd:N), a pipe")
		fmt.Fprintln(os.Stderr, "  (pipe:PATH), or a program (exec:CMD); also set by WEAVERSSH_SSH_CONFIG_SOURCE or .wv.")
		fmt.Fprintln(os.Stderr, "  Set WEAVERSSH_CONNECTION_SCAN_BIN to use the service-dock wizard instead.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	spec := resolveSSHConfigSpec(*sshConfig)

	if *importFlag {
		scan, err := runWizardScan(spec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "connections: %v\n", err)
			return 1
		}
		return importDiscovered(scan)
	}

	if *jsonOut {
		out, err := rawWizardScan(spec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "connections: %v\n", err)
			return 1
		}
		os.Stdout.Write(out)
		return 0
	}

	scan, err := runWizardScan(spec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connections: %v\n", err)
		return 1
	}
	printScan(scan)
	return 0
}

// importDiscovered records every discovered profile in the local store.
func importDiscovered(scan *Scan) int {
	if len(scan.DiscoveredProfiles) == 0 {
		fmt.Fprintln(os.Stderr, "connections: no discovered profiles to import")
		return 1
	}
	store, err := loadConnStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "connections: %v\n", err)
		return 1
	}
	added := 0
	for _, p := range scan.DiscoveredProfiles {
		if strings.TrimSpace(p.Name) == "" || strings.TrimSpace(p.SSHHost) == "" {
			continue
		}
		store = upsertProfile(store, p)
		added++
	}
	if err := saveConnStore(store); err != nil {
		fmt.Fprintf(os.Stderr, "connections: %v\n", err)
		return 1
	}
	fmt.Printf("imported %d profile(s) into %s\n", added, connectionsStorePath())
	return 0
}

func printConnectionsHelp() {
	fmt.Fprintln(os.Stderr, `usage: wv connections <command> [options]
       wv connections --node node/node1,node/node2[,node/node3] [--name NAME] [--number N] [-l KEY=VALUE]

Direct node sequence:
  --node/--nodes NODE[,NODE...]          define an ordered jump chain directly
  --name/--label NAME                    human chain label (default: chain-N)
  --number N                             stable positive chain number (default: next)
  -l, --set-label KEY=VALUE              Kubernetes-style labels for selection
  --append                               append nodes to an existing/active chain

Connection commands:
  scan [--json]                         autodetect identities/configs/profiles
  list [--json]                         list locally configured profiles
  set NAME [flags]                      create or update a local profile
  configure NAME [flags]                alias for set
  use NAME [--print-env]                mark a profile as active
  show [NAME] [--json]                  show a profile (default: active)
  current [--json]                      show the active profile
  capabilities [--version V] [--json]   show native capabilities by version
  upgrade [NAME] [--to V] [--dry-run]   upgrade a profile to a newer version
  downgrade [NAME] --to V --allow-loss  downgrade a profile and drop newer caps

Set/configure flags:
  --host HOST                           SSH host
  --user USER                           SSH user
  --port PORT                           SSH port (default 22)
  --identity-file PATH                  local SSH identity file
  --repo-root PATH                      local repo root associated with this profile
  --adapter NAME                        adapter name, e.g. openSSH
  --credential-provider NAME            credential provider, e.g. sshAgent
  --ninep-port PORT                     9P/VFS port (default 5640)
  --description TEXT                    human description
  --tag TAG                             repeatable profile tag
  -l, --set-label KEY=VALUE             Kubernetes-style profile label; repeatable
  --active                              also mark this profile active

Store:
  WEAVERSSH_CONNECTIONS_FILE overrides the default store path.`)
}

type tagList []string

func (t *tagList) String() string {
	return strings.Join(*t, ",")
}

func (t *tagList) Set(v string) error {
	v = strings.TrimSpace(v)
	if v != "" {
		*t = append(*t, v)
	}
	return nil
}

func cmdConnectionsList(args []string) int {
	fs := flag.NewFlagSet("connections list", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv connections list [--json]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	store, err := loadConnStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "connections list: %v\n", err)
		return 1
	}
	if *jsonOut {
		return printJSON(store)
	}
	fmt.Printf("store: %s\n", connectionsStorePath())
	if len(store.Profiles) == 0 {
		fmt.Println("profiles: none")
	} else {
		fmt.Println("profiles:")
		for _, p := range store.Profiles {
			mark := " "
			if p.Name == store.Active {
				mark = "*"
			}
			fmt.Printf("  %s %s  %s@%s:%d\n", mark, p.Name, orDash(p.SSHUser), orDash(p.SSHHost), portOrDefault(p.SSHPort))
		}
	}
	if len(store.Chains) == 0 {
		fmt.Println("chains: none")
	} else {
		fmt.Println("chains:")
		for _, chain := range store.Chains {
			mark := " "
			if chain.Label == store.ActiveChain {
				mark = "*"
			}
			fmt.Printf("  %s #%d %s  %s\n", mark, chain.Number, chain.Label, formatChainNodes(chain.Nodes))
		}
	}
	return 0
}

func cmdConnectionsSet(args []string) int {
	leadingName, parseArgs := splitLeadingName(args)
	fs := flag.NewFlagSet("connections set", flag.ContinueOnError)
	host := fs.String("host", "", "SSH host")
	user := fs.String("user", "", "SSH user")
	port := fs.Int("port", 22, "SSH port")
	identityFile := fs.String("identity-file", "", "local SSH identity file")
	repoRoot := fs.String("repo-root", "", "local repo root")
	adapter := fs.String("adapter", "openSSH", "adapter name")
	credentialProvider := fs.String("credential-provider", "", "credential provider")
	ninePPort := fs.Int("ninep-port", 5640, "9P/VFS port")
	description := fs.String("description", "", "description")
	active := fs.Bool("active", false, "mark this profile active")
	var tags tagList
	var labels labelAssignments
	fs.Var(&tags, "tag", "profile tag (repeatable)")
	fs.Var(&labels, "set-label", "Kubernetes-style label KEY=VALUE; repeatable")
	fs.Var(&labels, "l", "short alias for --set-label")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv connections set NAME [--host H] [--user U] [--identity-file PATH] [flags]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(parseArgs); err != nil {
		return 2
	}
	name := leadingName
	if name == "" && fs.NArg() == 1 {
		name = fs.Arg(0)
	} else if name != "" && fs.NArg() == 0 {
		// Name was supplied before flags.
	} else {
		fs.Usage()
		return 2
	}
	name = strings.TrimSpace(name)
	if name == "" {
		fmt.Fprintln(os.Stderr, "connections set: NAME cannot be empty")
		return 2
	}
	if *port <= 0 {
		fmt.Fprintln(os.Stderr, "connections set: --port must be positive")
		return 2
	}
	if *ninePPort <= 0 {
		fmt.Fprintln(os.Stderr, "connections set: --ninep-port must be positive")
		return 2
	}
	store, err := loadConnStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "connections set: %v\n", err)
		return 1
	}
	visited := visitedFlags(fs)
	profile, _, found := findProfile(store, name)
	if !found {
		profile = ConnProfile{
			Name:         name,
			Version:      connLatestVersion,
			SSHPort:      22,
			Adapter:      "openSSH",
			NinePPort:    5640,
			Capabilities: capabilitiesForVersion(connLatestVersion),
		}
	}
	if visited["description"] {
		profile.Description = strings.TrimSpace(*description)
	}
	if visited["host"] {
		profile.SSHHost = strings.TrimSpace(*host)
	}
	if visited["user"] {
		profile.SSHUser = strings.TrimSpace(*user)
	}
	if visited["port"] {
		profile.SSHPort = *port
	}
	if visited["identity-file"] {
		profile.IdentityFile = strings.TrimSpace(*identityFile)
	}
	if visited["repo-root"] {
		profile.RepoRoot = strings.TrimSpace(*repoRoot)
	}
	if visited["adapter"] {
		profile.Adapter = strings.TrimSpace(*adapter)
	}
	if visited["credential-provider"] {
		profile.CredentialProvider = strings.TrimSpace(*credentialProvider)
	}
	if visited["ninep-port"] {
		profile.NinePPort = *ninePPort
	}
	if visited["tag"] {
		profile.Tags = tags
	}
	if visited["set-label"] || visited["l"] {
		profile.Labels = mergeLabels(profile.Labels, labels)
	}
	if profile.Version == "" {
		if found {
			profile.Version = connLegacyVersion
		} else {
			profile.Version = connLatestVersion
		}
	}
	if len(profile.Capabilities) == 0 {
		profile.Capabilities = capabilitiesForVersion(profile.Version)
	}
	store = upsertProfile(store, profile)
	if *active {
		store.Active = name
	}
	if err := saveConnStore(store); err != nil {
		fmt.Fprintf(os.Stderr, "connections set: %v\n", err)
		return 1
	}
	fmt.Printf("profile saved: %s\n", name)
	fmt.Printf("store: %s\n", connectionsStorePath())
	if *active {
		fmt.Printf("active: %s\n", name)
	}
	return 0
}

func cmdConnectionsUse(args []string) int {
	leadingName, parseArgs := splitLeadingName(args)
	fs := flag.NewFlagSet("connections use", flag.ContinueOnError)
	printEnv := fs.Bool("print-env", false, "print shell exports for the selected profile")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv connections use NAME [--print-env]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(parseArgs); err != nil {
		return 2
	}
	name := leadingName
	if name == "" && fs.NArg() == 1 {
		name = fs.Arg(0)
	} else if name != "" && fs.NArg() == 0 {
		// Name was supplied before flags.
	} else {
		fs.Usage()
		return 2
	}
	name = strings.TrimSpace(name)
	store, err := loadConnStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "connections use: %v\n", err)
		return 1
	}
	profile, _, ok := findProfile(store, name)
	if !ok {
		fmt.Fprintf(os.Stderr, "connections use: profile %q not found\n", name)
		return 1
	}
	store.Active = name
	if err := saveConnStore(store); err != nil {
		fmt.Fprintf(os.Stderr, "connections use: %v\n", err)
		return 1
	}
	if *printEnv {
		printProfileEnv(profile)
		return 0
	}
	fmt.Printf("active profile: %s\n", name)
	printProfile(profile)
	return 0
}

func cmdConnectionsShow(args []string) int {
	leadingName, parseArgs := splitLeadingName(args)
	fs := flag.NewFlagSet("connections show", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv connections show [NAME] [--json]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(parseArgs); err != nil {
		return 2
	}
	name := leadingName
	if name == "" && fs.NArg() == 1 {
		name = fs.Arg(0)
	} else if name != "" && fs.NArg() == 0 {
		// Name was supplied before flags.
	} else if fs.NArg() > 0 {
		fs.Usage()
		return 2
	}
	store, err := loadConnStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "connections show: %v\n", err)
		return 1
	}
	profile, err := activeOrNamedProfile(store, name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connections show: %v\n", err)
		return 1
	}
	if *jsonOut {
		return printJSON(profile)
	}
	printProfile(profile)
	return 0
}

func cmdConnectionsCurrent(args []string) int {
	fs := flag.NewFlagSet("connections current", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv connections current [--json]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	store, err := loadConnStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "connections current: %v\n", err)
		return 1
	}
	profile, err := activeOrNamedProfile(store, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "connections current: %v\n", err)
		return 1
	}
	if *jsonOut {
		return printJSON(profile)
	}
	fmt.Printf("active: %s\n", store.Active)
	printProfile(profile)
	return 0
}

func cmdConnectionsCapabilities(args []string) int {
	fs := flag.NewFlagSet("connections capabilities", flag.ContinueOnError)
	version := fs.String("version", "", "profile version to inspect (default: all)")
	jsonOut := fs.Bool("json", false, "emit JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv connections capabilities [--version VERSION] [--json]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	if *version != "" {
		spec, ok := connectionVersionSpec(*version)
		if !ok {
			fmt.Fprintf(os.Stderr, "connections capabilities: unsupported version %q\n", *version)
			return 1
		}
		if *jsonOut {
			return printJSON(spec)
		}
		printVersionSpec(spec)
		return 0
	}
	specs := make([]ConnVersionSpec, 0, len(connVersionSpecs))
	for _, v := range supportedConnectionVersions() {
		specs = append(specs, connVersionSpecs[v])
	}
	if *jsonOut {
		return printJSON(specs)
	}
	for i, spec := range specs {
		if i > 0 {
			fmt.Println()
		}
		printVersionSpec(spec)
	}
	return 0
}

func cmdConnectionsMigrate(args []string, upgrade bool) int {
	leadingName, parseArgs := splitLeadingName(args)
	fs := flag.NewFlagSet("connections migrate", flag.ContinueOnError)
	to := fs.String("to", "", "target profile version")
	dryRun := fs.Bool("dry-run", false, "show the migration without writing")
	allowLoss := fs.Bool("allow-loss", false, "allow downgrade to drop newer capabilities")
	fs.Usage = func() {
		dir := "upgrade"
		if !upgrade {
			dir = "downgrade"
		}
		fmt.Fprintf(os.Stderr, "usage: wv connections %s [NAME] --to VERSION [--dry-run] [--allow-loss]\n", dir)
		fs.PrintDefaults()
	}
	if err := fs.Parse(parseArgs); err != nil {
		return 2
	}
	name := leadingName
	if name == "" && fs.NArg() == 1 {
		name = fs.Arg(0)
	} else if name != "" && fs.NArg() == 0 {
		// Name was supplied before flags.
	} else if fs.NArg() > 0 {
		fs.Usage()
		return 2
	}
	store, err := loadConnStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "connections migrate: %v\n", err)
		return 1
	}
	profile, err := activeOrNamedProfile(store, name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connections migrate: %v\n", err)
		return 1
	}
	if strings.TrimSpace(*to) == "" {
		if upgrade {
			*to = connLatestVersion
		} else {
			fs.Usage()
			return 2
		}
	}
	next, lost, err := migrateProfileVersion(profile, *to, upgrade, *allowLoss)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connections migrate: %v\n", err)
		return 1
	}
	fmt.Printf("profile: %s\n", profile.Name)
	fmt.Printf("from:    %s\n", profileVersion(profile))
	fmt.Printf("to:      %s\n", next.Version)
	if len(lost) > 0 {
		fmt.Printf("dropped capabilities: %s\n", strings.Join(lost, ","))
	}
	if *dryRun {
		fmt.Println("status:  dry-run (store not changed)")
		return 0
	}
	store = upsertProfile(store, next)
	if err := saveConnStore(store); err != nil {
		fmt.Fprintf(os.Stderr, "connections migrate: %v\n", err)
		return 1
	}
	fmt.Println("status:  saved")
	return 0
}

func migrateProfileVersion(p ConnProfile, to string, upgrade bool, allowLoss bool) (ConnProfile, []string, error) {
	to = strings.TrimSpace(to)
	if _, ok := connectionVersionSpec(to); !ok {
		return ConnProfile{}, nil, fmt.Errorf("unsupported target version %q", to)
	}
	from := profileVersion(p)
	if _, ok := connectionVersionSpec(from); !ok {
		return ConnProfile{}, nil, fmt.Errorf("profile %q has unsupported version %q", p.Name, from)
	}
	fromIndex, toIndex := connectionVersionIndex(from), connectionVersionIndex(to)
	if fromIndex == toIndex {
		p.Version = to
		if len(p.Capabilities) == 0 {
			p.Capabilities = capabilitiesForVersion(to)
		}
		return p, nil, nil
	}
	if upgrade && toIndex < fromIndex {
		return ConnProfile{}, nil, fmt.Errorf("target %s is older than current %s; use downgrade", to, from)
	}
	if !upgrade && toIndex > fromIndex {
		return ConnProfile{}, nil, fmt.Errorf("target %s is newer than current %s; use upgrade", to, from)
	}
	targetCaps := capabilitiesForVersion(to)
	lost := lostCapabilityIDs(p, targetCaps)
	if !upgrade && len(lost) > 0 && !allowLoss {
		return ConnProfile{}, lost, fmt.Errorf("downgrade would drop capabilities %s; pass --allow-loss", strings.Join(lost, ","))
	}
	p.Version = to
	p.Capabilities = targetCaps
	return p, lost, nil
}

func lostCapabilityIDs(p ConnProfile, target []ConnCapability) []string {
	source := p.Capabilities
	if len(source) == 0 {
		source = capabilitiesForVersion(profileVersion(p))
	}
	targetIDs := map[string]bool{}
	for _, cap := range target {
		targetIDs[cap.ID] = true
	}
	var lost []string
	for _, cap := range source {
		if !targetIDs[cap.ID] {
			lost = append(lost, cap.ID)
		}
	}
	sort.Strings(lost)
	return lost
}

func printJSON(v any) int {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "json: %v\n", err)
		return 1
	}
	fmt.Println(string(data))
	return 0
}

func printProfile(p ConnProfile) {
	fmt.Printf("profile:   %s\n", orDash(p.Name))
	fmt.Printf("version:   %s\n", profileVersion(p))
	if p.Description != "" {
		fmt.Printf("desc:      %s\n", p.Description)
	}
	fmt.Printf("ssh:       %s@%s:%d\n", orDash(p.SSHUser), orDash(p.SSHHost), portOrDefault(p.SSHPort))
	if p.IdentityFile != "" {
		fmt.Printf("identity:  %s\n", p.IdentityFile)
	}
	if p.CredentialProvider != "" {
		fmt.Printf("credential: %s\n", p.CredentialProvider)
	}
	if p.Adapter != "" {
		fmt.Printf("adapter:   %s\n", p.Adapter)
	}
	if p.NinePPort > 0 {
		fmt.Printf("9p:        127.0.0.1:%d\n", p.NinePPort)
	}
	if p.RepoRoot != "" {
		fmt.Printf("repo-root: %s\n", p.RepoRoot)
	}
	if len(p.Tags) > 0 {
		fmt.Printf("tags:      %s\n", strings.Join(p.Tags, ","))
	}
	if len(p.Labels) > 0 {
		fmt.Printf("labels:    %s\n", formatLabels(p.Labels))
	}
	caps := p.Capabilities
	if len(caps) == 0 {
		caps = capabilitiesForVersion(profileVersion(p))
	}
	if len(caps) > 0 {
		ids := make([]string, 0, len(caps))
		for _, cap := range caps {
			ids = append(ids, cap.ID)
		}
		sort.Strings(ids)
		fmt.Printf("caps:      %s\n", strings.Join(ids, ","))
	}
}

func printVersionSpec(spec ConnVersionSpec) {
	fmt.Printf("version: %s\n", spec.Version)
	if spec.Description != "" {
		fmt.Printf("desc:    %s\n", spec.Description)
	}
	fmt.Println("capabilities:")
	for _, cap := range spec.Capabilities {
		native := "external"
		if cap.Native {
			native = "native"
		}
		fmt.Printf("  - %s [%s]", cap.ID, native)
		if cap.Since != "" {
			fmt.Printf(" since=%s", cap.Since)
		}
		if cap.Description != "" {
			fmt.Printf(" — %s", cap.Description)
		}
		fmt.Println()
	}
}

func printProfileEnv(p ConnProfile) {
	fmt.Printf("export WEAVERSSH_CONNECTION=%q\n", p.Name)
	if p.SSHHost != "" {
		fmt.Printf("export WEAVERSSH_SSH_HOST=%q\n", p.SSHHost)
	}
	if p.SSHUser != "" {
		fmt.Printf("export WEAVERSSH_SSH_USER=%q\n", p.SSHUser)
	}
	if p.SSHPort > 0 {
		fmt.Printf("export WEAVERSSH_SSH_PORT=%q\n", fmt.Sprint(p.SSHPort))
	}
	if p.IdentityFile != "" {
		fmt.Printf("export WEAVERSSH_IDENTITY_FILE=%q\n", p.IdentityFile)
	}
	if p.NinePPort > 0 {
		fmt.Printf("export WEAVERSSH_9P_PORT=%q\n", fmt.Sprint(p.NinePPort))
	}
}

func portOrDefault(port int) int {
	if port > 0 {
		return port
	}
	return 22
}

func splitLeadingName(args []string) (string, []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return "", args
}

func visitedFlags(fs *flag.FlagSet) map[string]bool {
	visited := map[string]bool{}
	fs.Visit(func(f *flag.Flag) {
		visited[f.Name] = true
	})
	return visited
}

func printScan(s *Scan) {
	p := s.Profile
	fmt.Printf("profile:   %s", orDash(p.Name))
	if p.Description != "" {
		fmt.Printf("  — %s", p.Description)
	}
	fmt.Println()
	if p.SSHHost != "" || p.SSHUser != "" {
		fmt.Printf("ssh:       %s@%s:%d\n", orDash(p.SSHUser), orDash(p.SSHHost), p.SSHPort)
	}
	if p.IdentityFile != "" {
		fmt.Printf("identity:  %s\n", p.IdentityFile)
	}
	if p.RepoRoot != "" {
		fmt.Printf("repo-root: %s\n", p.RepoRoot)
	}

	a := s.Assessment
	fmt.Printf("readiness: %s", orDash(a.State))
	if a.Summary != "" {
		fmt.Printf(" (%s)", a.Summary)
	}
	fmt.Println()
	if !a.OK && a.NextAction != "" {
		fmt.Printf("next:      %s\n", a.NextAction)
	}

	if len(a.IdentityFiles) > 0 {
		fmt.Println("identity files:")
		for _, f := range a.IdentityFiles {
			fmt.Printf("  - %s\n", f)
		}
	}
	if len(s.CredentialChoices) > 0 {
		fmt.Println("credential choices:")
		for _, c := range s.CredentialChoices {
			loc := c.Path
			if loc == "" {
				loc = c.Source
			}
			fmt.Printf("  - [%s] %s (%s) %s\n", c.State, c.Label, c.Kind, loc)
		}
	}
	if len(s.SSHConfigSources) > 0 {
		fmt.Printf("ssh_config sources: %d (first: %s)\n", len(s.SSHConfigSources), s.SSHConfigSources[0].Path)
	}
	if len(s.DiscoveredProfiles) > 0 {
		fmt.Printf("discovered %d connection(s):\n", len(s.DiscoveredProfiles))
		for _, p := range s.DiscoveredProfiles {
			target := p.SSHHost
			if p.SSHUser != "" {
				target = p.SSHUser + "@" + target
			}
			if p.SSHPort != 0 && p.SSHPort != 22 {
				target = fmt.Sprintf("%s:%d", target, p.SSHPort)
			}
			src := ""
			if p.Labels != nil {
				src = p.Labels["source"]
			}
			fmt.Printf("  - %-24s %-28s [%s]\n", p.Name, target, src)
		}
	}
	if s.ProfilesDir != "" {
		fmt.Printf("profiles:  %s  (store: %s)\n", s.ProfilesDir, s.StorePath)
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
