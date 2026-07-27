package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	depsDefaultHomePrefix = "~/.weaverssh"
	depsDefaultGoVersion  = "1.24.4"
)

var (
	depsLinux = map[string][]string{
		"apt":    {"ca-certificates", "openssh-client", "xauth"},
		"dnf":    {"ca-certificates", "openssh-clients", "xorg-x11-xauth"},
		"yum":    {"ca-certificates", "openssh-clients", "xorg-x11-xauth"},
		"zypper": {"ca-certificates", "openssh", "xauth"},
		"pacman": {"ca-certificates", "openssh", "xorg-xauth"},
		"apk":    {"ca-certificates", "openssh-client", "xauth"},
	}
	depsMacOS = map[string][]string{
		"brew": {"xquartz"},
	}
	depsWindows = map[string][]string{
		"winget": {"Git.Git"},
		"choco":  {"git"},
	}
	depsBSD = map[string][]string{
		"pkg":     {"ca_root_nss", "openssh-portable", "xauth"},
		"pkg_add": {"xauth"},
	}
	depsAIX = map[string][]string{
		"installp": {"openssh", "xauth"},
	}
)

type DepsStatus struct {
	Package      string   `json:"package"`
	Installed    bool     `json:"installed"`
	State        string   `json:"state"`
	Detail       string   `json:"detail"`
	QueryCommand []string `json:"query_command"`
	Error        string   `json:"error,omitempty"`
}

type DepsPlan struct {
	Platform          string         `json:"platform"`
	PackageManager    string         `json:"package_manager"`
	InstallMethod     string         `json:"install_method"`
	HomePrefix        string         `json:"home_prefix"`
	Packages          []string       `json:"packages"`
	SelectedPackages  []string       `json:"selected_packages"`
	InstalledPackages []string       `json:"installed_packages"`
	MissingPackages   []string       `json:"missing_packages"`
	UnknownPackages   []string       `json:"unknown_packages"`
	Commands          [][]string     `json:"commands"`
	RequiresPrivilege bool           `json:"requires_privilege"`
	Action            string         `json:"action"`
	Replace           bool           `json:"replace"`
	Force             bool           `json:"force"`
	OnlyMissing       bool           `json:"only_missing"`
	StatusSummary     map[string]int `json:"status_summary,omitempty"`
	Statuses          []DepsStatus   `json:"statuses,omitempty"`
	Safeguards        []string       `json:"safeguards,omitempty"`
}

type depsOptions struct {
	command      string
	method       string
	homePrefix   string
	manager      string
	includeBuild bool
	yes          bool
	replace      bool
	force        bool
	confirmForce bool
	dryRun       bool
	all          bool
	logFile      string
	jsonOut      bool
}

func cmdDeps(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "help", "-h", "--help":
			printDepsHelp()
			return 0
		case "plan", "status", "install":
			return cmdDepsRun(args[0], args[1:])
		}
		if !strings.HasPrefix(args[0], "-") {
			fmt.Fprintf(os.Stderr, "deps: unknown command %q\n", args[0])
			printDepsHelp()
			return 2
		}
	}
	return cmdDepsRun("status", args)
}

func cmdDepsRun(command string, args []string) int {
	opts, err := parseDepsFlags(command, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	inspect := opts.command == "status" || opts.command == "install" || opts.all
	plan := buildDepsPlan(opts, inspect)
	logDeps(opts.logFile, opts.command, plan)
	if opts.jsonOut {
		if rc := printJSON(plan); rc != 0 {
			return rc
		}
	} else {
		printDepsPlan(plan)
	}
	if opts.command != "install" {
		return 0
	}
	if opts.dryRun {
		logDeps(opts.logFile, "install_dry_run", map[string]any{"commands": plan.Commands})
		return 0
	}
	if opts.force && !opts.confirmForce {
		logDeps(opts.logFile, "force_denied", map[string]any{"reason": "missing --confirm-force"})
		fmt.Fprintln(os.Stderr, "install --force requires --confirm-force")
		return 2
	}
	if plan.InstallMethod == "home" {
		unsupported := unsupportedHomePackages(plan.SelectedPackages)
		if len(unsupported) > 0 {
			logDeps(opts.logFile, "home_unsupported_denied", map[string]any{"packages": unsupported})
			fmt.Fprintf(os.Stderr, "home method cannot install these missing tools: %s; install them manually or use --method package-manager\n", strings.Join(unsupported, ", "))
			return 2
		}
		if err := runDepsHomeInstall(plan, opts); err != nil {
			fmt.Fprintf(os.Stderr, "deps install: %v\n", err)
			return 1
		}
		return 0
	}
	if err := runDepsCommands(plan.Commands, opts.logFile); err != nil {
		fmt.Fprintf(os.Stderr, "deps install: %v\n", err)
		return 1
	}
	return 0
}

func parseDepsFlags(command string, args []string) (depsOptions, error) {
	opts := depsOptions{command: command, method: "auto", homePrefix: depsDefaultHomePrefix}
	fs := flag.NewFlagSet("wv deps "+command, flag.ContinueOnError)
	fs.StringVar(&opts.method, "method", opts.method, "install method: home, package-manager, or auto")
	fs.StringVar(&opts.homePrefix, "home-prefix", opts.homePrefix, "home install prefix for --method home")
	fs.StringVar(&opts.manager, "manager", "", "package manager: apt, dnf, yum, zypper, pacman, apk, brew, winget, choco, pkg, pkg_add, or installp")
	fs.BoolVar(&opts.includeBuild, "include-build", false, "include Go/build/package tooling")
	fs.BoolVar(&opts.yes, "yes", false, "use non-interactive yes flags where supported")
	fs.BoolVar(&opts.replace, "replace", false, "use reinstall/upgrade semantics where supported")
	fs.BoolVar(&opts.force, "force", false, "add stronger replacement flags where supported")
	fs.BoolVar(&opts.confirmForce, "confirm-force", false, "required with install --force")
	fs.BoolVar(&opts.dryRun, "dry-run", false, "with install, print/log the plan without running commands")
	fs.BoolVar(&opts.all, "all", false, "target all configured packages instead of only missing/unknown packages")
	fs.StringVar(&opts.logFile, "log-file", defaultDepsLogPath(), "append JSONL audit log")
	fs.BoolVar(&opts.jsonOut, "json", false, "emit JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: wv deps %s [flags]\n", command)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return opts, err
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return opts, fmt.Errorf("unexpected args")
	}
	return opts, nil
}

func printDepsHelp() {
	fmt.Fprintln(os.Stderr, `usage: wv deps <plan|status|install> [flags]

Default behavior is home-only: inspect PATH and ~/.weaverssh, write logs under
~/.weaverssh/logs, and install only tools that can be safely provisioned in the
user home prefix. Use --method package-manager --manager NAME for OS package
manager operations.`)
}

func buildDepsPlan(opts depsOptions, inspect bool) DepsPlan {
	platformName, detectedManager := detectDepsPackageManager(opts.manager)
	method := resolveDepsMethod(opts.method, opts.manager)
	manager := detectedManager
	if method == "home" {
		manager = "home"
	}
	packages := depsPackages(manager, opts.includeBuild, method)
	var statuses []DepsStatus
	if inspect {
		if method == "home" {
			statuses = inspectDepsHome(packages, opts.homePrefix)
		} else {
			statuses = inspectDepsPackages(manager, packages)
		}
	}
	installed, missing, unknown := classifyDeps(statuses)
	effectiveOnlyMissing := !opts.all && !opts.replace && !opts.force
	selected := selectDepsPackages(packages, statuses, missing, unknown, opts.replace, opts.force, effectiveOnlyMissing)
	privileged := false
	if method == "package-manager" {
		privileged = depsRequiresPrivilege(manager)
	}
	commands := depsCommands(manager, method, selected, opts)
	safeguards := depsSafeguards(method, selected, inspect, opts, effectiveOnlyMissing)
	return DepsPlan{
		Platform: platformName, PackageManager: manager, InstallMethod: method, HomePrefix: opts.homePrefix,
		Packages: packages, SelectedPackages: selected, InstalledPackages: installed, MissingPackages: missing, UnknownPackages: unknown,
		Commands: commands, RequiresPrivilege: privileged, Action: map[bool]string{true: "replace", false: "install"}[opts.replace],
		Replace: opts.replace, Force: opts.force, OnlyMissing: effectiveOnlyMissing, StatusSummary: depsStatusSummary(statuses), Statuses: statuses, Safeguards: safeguards,
	}
}

func resolveDepsMethod(method, manager string) string {
	method = strings.TrimSpace(strings.ToLower(method))
	if method == "" || method == "auto" {
		if manager != "" {
			return "package-manager"
		}
		return "home"
	}
	if method == "package-manager" || method == "home" {
		return method
	}
	return "home"
}

func depsPackages(manager string, includeBuild bool, method string) []string {
	if method == "home" {
		pkgs := []string{"ssh", "xauth"}
		if includeBuild {
			pkgs = append(pkgs, "go", "git", "make")
		}
		return dedupeStrings(pkgs)
	}
	var pkgs []string
	if v, ok := depsLinux[manager]; ok {
		pkgs = append(pkgs, v...)
		if includeBuild {
			switch manager {
			case "apt":
				pkgs = append(pkgs, "golang", "make", "git", "python3", "python3-venv", "dpkg-dev", "rpm", "zstd", "zip")
			case "dnf", "yum":
				pkgs = append(pkgs, "golang", "make", "git", "python3", "rpm-build", "zstd", "zip")
			case "zypper":
				pkgs = append(pkgs, "go", "make", "git", "python3", "rpm-build", "zstd", "zip")
			case "pacman":
				pkgs = append(pkgs, "go", "make", "git", "python", "fakeroot", "zstd", "zip")
			case "apk":
				pkgs = append(pkgs, "go", "make", "git", "python3", "rpm", "zstd", "zip")
			}
		}
	} else if v, ok := depsMacOS[manager]; ok {
		pkgs = append(pkgs, v...)
		if includeBuild {
			pkgs = append(pkgs, "go", "python", "rpm", "zstd")
		}
	} else if v, ok := depsWindows[manager]; ok {
		pkgs = append(pkgs, v...)
		if includeBuild {
			switch manager {
			case "winget":
				pkgs = append(pkgs, "GoLang.Go", "Python.Python.3.12")
			case "choco":
				pkgs = append(pkgs, "golang", "python")
			}
		}
	} else if v, ok := depsBSD[manager]; ok {
		pkgs = append(pkgs, v...)
		if includeBuild {
			switch manager {
			case "pkg":
				pkgs = append(pkgs, "go", "gmake", "git", "python3", "zip", "zstd")
			case "pkg_add":
				pkgs = append(pkgs, "go", "gmake", "git", "python3")
			}
		}
	} else if v, ok := depsAIX[manager]; ok {
		pkgs = append(pkgs, v...)
	}
	return dedupeStrings(pkgs)
}

func inspectDepsHome(packages []string, homePrefix string) []DepsStatus {
	var out []DepsStatus
	prefix := expandDepsHome(homePrefix)
	for _, pkg := range packages {
		query := []string{"command", "-v", pkg}
		if path, err := exec.LookPath(pkg); err == nil {
			out = append(out, DepsStatus{Package: pkg, Installed: true, State: "installed", Detail: path, QueryCommand: query})
			continue
		}
		for _, candidate := range depsHomeCandidates(pkg, prefix) {
			if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
				out = append(out, DepsStatus{Package: pkg, Installed: true, State: "installed", Detail: candidate, QueryCommand: query})
				goto next
			}
		}
		if depsHomeInstallable(pkg) {
			out = append(out, DepsStatus{Package: pkg, State: "missing", Detail: "missing; home installer can provide this tool", QueryCommand: query})
		} else {
			out = append(out, DepsStatus{Package: pkg, State: "missing", Detail: "missing; requires existing PATH tool or explicit package-manager install", QueryCommand: query})
		}
	next:
	}
	return out
}

func depsHomeCandidates(pkg, prefix string) []string {
	if pkg == "go" {
		return []string{filepath.Join(prefix, "toolchains", "go", "bin", "go"), filepath.Join(prefix, "bin", "go")}
	}
	if pkg == "xauth" {
		return []string{filepath.Join(prefix, "bin", "xauth"), "/opt/X11/bin/xauth", "/usr/X11/bin/xauth", "/usr/bin/xauth"}
	}
	return []string{filepath.Join(prefix, "bin", pkg)}
}

func depsHomeInstallable(pkg string) bool { return pkg == "go" }

func unsupportedHomePackages(pkgs []string) []string {
	var out []string
	for _, pkg := range pkgs {
		if !depsHomeInstallable(pkg) {
			out = append(out, pkg)
		}
	}
	return out
}

func inspectDepsPackages(manager string, packages []string) []DepsStatus {
	var out []DepsStatus
	for _, pkg := range packages {
		query := depsQueryCommand(manager, pkg)
		if len(query) == 0 {
			out = append(out, DepsStatus{Package: pkg, State: "unknown", Detail: "no query command available"})
			continue
		}
		if _, err := exec.LookPath(query[0]); err != nil {
			out = append(out, DepsStatus{Package: pkg, State: "unknown", Detail: "query tool not found: " + query[0], QueryCommand: query})
			continue
		}
		cmd := exec.Command(query[0], query[1:]...)
		b, err := cmd.CombinedOutput()
		text := strings.TrimSpace(string(b))
		installed := err == nil
		if manager == "apt" {
			installed = err == nil && strings.Contains(text, "install ok installed")
		} else if manager == "brew" && len(query) == 3 && query[1] == "list" && query[2] == "--cask" {
			installed = containsLineFold(text, pkg)
			if installed {
				text = "installed"
			} else {
				text = "missing"
			}
		} else if manager == "winget" || manager == "choco" {
			installed = err == nil && strings.Contains(strings.ToLower(text), strings.ToLower(pkg))
		}
		state := "missing"
		if installed {
			state = "installed"
		}
		detail := text
		if detail == "" {
			detail = state
		}
		st := DepsStatus{Package: pkg, Installed: installed, State: state, Detail: detail, QueryCommand: query}
		if err != nil {
			st.Error = detail
		}
		out = append(out, st)
	}
	return out
}

func depsQueryCommand(manager, pkg string) []string {
	switch manager {
	case "apt":
		return []string{"dpkg-query", "-W", "-f=${Status}", pkg}
	case "dnf", "yum", "zypper":
		return []string{"rpm", "-q", pkg}
	case "pacman":
		return []string{"pacman", "-Q", pkg}
	case "apk":
		return []string{"apk", "info", "-e", pkg}
	case "brew":
		if pkg == "xquartz" {
			return []string{"brew", "list", "--cask"}
		}
		return []string{"brew", "list", "--versions", pkg}
	case "winget":
		return []string{"winget", "list", "--id", pkg, "--exact"}
	case "choco":
		return []string{"choco", "list", "--local-only", "--exact", pkg}
	case "pkg":
		return []string{"pkg", "info", "-e", pkg}
	case "pkg_add":
		return []string{"pkg_info", "-e", pkg}
	case "installp":
		return []string{"lslpp", "-L", pkg}
	}
	return nil
}

func depsCommands(manager, method string, packages []string, opts depsOptions) [][]string {
	if len(packages) == 0 {
		return nil
	}
	if method == "home" {
		return depsHomeCommands(packages, opts.homePrefix, opts.includeBuild, opts.replace || opts.force)
	}
	sudo := []string{}
	if depsRequiresPrivilege(manager) {
		sudo = []string{"sudo"}
	}
	var cmds [][]string
	switch manager {
	case "apt":
		cmds = append(cmds, append([]string{}, append(sudo, "apt-get", "update")...))
		install := append([]string{}, append(sudo, "apt-get", "install")...)
		if opts.yes {
			install = append(install, "-y")
		}
		install = append(install, "--no-install-recommends")
		if opts.replace {
			install = append(install, "--reinstall")
		}
		if opts.force {
			install = append(install, "--allow-downgrades", "--allow-change-held-packages", "-o", "Dpkg::Options::=--force-confnew")
		}
		cmds = append(cmds, append(install, packages...))
	case "dnf", "yum":
		action := "install"
		if opts.replace {
			action = "reinstall"
		}
		cmd := append([]string{}, append(sudo, manager, action)...)
		if opts.yes {
			cmd = append(cmd, "-y")
		} else {
			cmd = append(cmd, "--assumeno")
		}
		if opts.force {
			cmd = append(cmd, "--allowerasing")
		}
		cmds = append(cmds, append(cmd, packages...))
	case "zypper":
		cmd := append([]string{}, append(sudo, "zypper", "install")...)
		if opts.yes {
			cmd = append(cmd, "-y")
		} else {
			cmd = append(cmd, "--dry-run")
		}
		if opts.replace || opts.force {
			cmd = append(cmd, "--force")
		}
		cmds = append(cmds, append(cmd, packages...))
	case "pacman":
		cmd := append([]string{}, append(sudo, "pacman")...)
		if opts.force {
			cmd = append(cmd, "-Syu")
		} else {
			cmd = append(cmd, "-Sy")
		}
		if !opts.replace {
			cmd = append(cmd, "--needed")
		}
		if opts.force {
			cmd = append(cmd, "--overwrite", "*")
		}
		if opts.yes {
			cmd = append(cmd, "--noconfirm")
		} else {
			cmd = append(cmd, "--print")
		}
		cmds = append(cmds, append(cmd, packages...))
	case "apk":
		cmd := append([]string{}, append(sudo, "apk")...)
		if opts.replace {
			cmd = append(cmd, "fix")
		} else {
			cmd = append(cmd, "add")
		}
		if opts.force {
			cmd = append(cmd, "--force-refresh")
		}
		cmds = append(cmds, append(cmd, packages...))
	case "brew":
		var formulae, casks []string
		for _, p := range packages {
			if p == "xquartz" {
				casks = append(casks, p)
			} else {
				formulae = append(formulae, p)
			}
		}
		verb := "install"
		if opts.replace || opts.force {
			verb = "reinstall"
		}
		if len(formulae) > 0 {
			cmds = append(cmds, append([]string{"brew", verb}, formulae...))
		}
		for _, c := range casks {
			cmds = append(cmds, []string{"brew", verb, "--cask", c})
		}
	case "winget":
		for _, p := range packages {
			cmd := []string{"winget", "install", "--id", p, "--exact"}
			if opts.replace || opts.force {
				cmd = append(cmd, "--force")
			}
			if opts.yes {
				cmd = append(cmd, "--silent")
			} else {
				cmd = append(cmd, "--interactive")
			}
			cmds = append(cmds, cmd)
		}
	case "choco":
		verb := "install"
		if opts.replace || opts.force {
			verb = "upgrade"
		}
		for _, p := range packages {
			cmd := []string{"choco", verb, p}
			if opts.yes {
				cmd = append(cmd, "-y")
			} else {
				cmd = append(cmd, "--noop")
			}
			if opts.force {
				cmd = append(cmd, "--force")
			}
			cmds = append(cmds, cmd)
		}
	case "pkg":
		cmd := append([]string{}, append(sudo, "pkg", "install")...)
		if opts.yes {
			cmd = append(cmd, "-y")
		} else {
			cmd = append(cmd, "-n")
		}
		if opts.replace || opts.force {
			cmd = append(cmd, "-f")
		}
		cmds = append(cmds, append(cmd, packages...))
	case "pkg_add":
		cmd := append([]string{}, append(sudo, "pkg_add")...)
		if opts.yes {
			cmd = append(cmd, "-I")
		} else {
			cmd = append(cmd, "-n")
		}
		cmds = append(cmds, append(cmd, packages...))
	case "installp":
		cmds = append(cmds, []string{"echo", "AIX installp requires approved local media; install OpenSSH and xauth from the organization package source"})
	}
	return cmds
}

func depsHomeCommands(packages []string, homePrefix string, includeBuild, replace bool) [][]string {
	prefix := expandDepsHome(homePrefix)
	wv := depsSelfCommand()
	cmds := [][]string{{"mkdir", "-p", filepath.Join(prefix, "bin"), filepath.Join(prefix, "toolchains"), filepath.Join(prefix, "logs"), filepath.Join(prefix, "tmp")}}
	for _, p := range packages {
		if p == "go" {
			cmds = append(cmds, []string{wv, "deps", "install", "--include-build", "--home-prefix", prefix})
		}
	}
	if includeBuild {
		cmds = append(cmds, []string{"sh", "-c", fmt.Sprintf("printf %%s\\n 'export PATH=\"%s/bin:$PATH\"' > %s", prefix, filepath.Join(prefix, "env.sh"))})
	}
	return cmds
}

func depsSelfCommand() string {
	if exe, err := os.Executable(); err == nil && strings.TrimSpace(exe) != "" {
		return exe
	}
	return "wv"
}

func runDepsHomeInstall(plan DepsPlan, opts depsOptions) error {
	prefix := expandDepsHome(opts.homePrefix)
	for _, dir := range []string{"bin", "toolchains", "logs", "tmp"} {
		if err := os.MkdirAll(filepath.Join(prefix, dir), 0o755); err != nil {
			return err
		}
	}
	for _, pkg := range plan.SelectedPackages {
		if pkg == "go" {
			if err := installGoHome(prefix, opts.replace || opts.force, opts.logFile); err != nil {
				return err
			}
		}
	}
	if opts.includeBuild {
		if err := os.WriteFile(filepath.Join(prefix, "env.sh"), []byte(fmt.Sprintf("export PATH=\"%s/bin:$PATH\"\n", prefix)), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func installGoHome(prefix string, replace bool, logFile string) error {
	goRoot := filepath.Join(prefix, "toolchains", "go")
	goBin := filepath.Join(goRoot, "bin", "go")
	if !replace {
		if st, err := os.Stat(goBin); err == nil && !st.IsDir() {
			return nil
		}
	}
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return fmt.Errorf("unsupported Go bootstrap OS: %s", runtime.GOOS)
	}
	arch := runtime.GOARCH
	if arch != "amd64" && arch != "arm64" {
		return fmt.Errorf("unsupported Go bootstrap arch: %s", arch)
	}
	version := os.Getenv("WEAVERSSH_GO_VERSION")
	if version == "" {
		version = depsDefaultGoVersion
	}
	archive := fmt.Sprintf("go%s.%s-%s.tar.gz", version, runtime.GOOS, arch)
	url := "https://go.dev/dl/" + archive
	dest := filepath.Join(prefix, "tmp", archive)
	logDeps(logFile, "home_go_download_start", map[string]any{"url": url, "dest": dest})
	if err := downloadFile(url, dest); err != nil {
		return err
	}
	if replace {
		if err := os.RemoveAll(goRoot); err != nil {
			return err
		}
	}
	if err := extractGoArchive(dest, filepath.Join(prefix, "toolchains")); err != nil {
		return err
	}
	if err := os.Symlink(goBin, filepath.Join(prefix, "bin", "go")); err != nil {
		if !os.IsExist(err) {
			return err
		}
		_ = os.Remove(filepath.Join(prefix, "bin", "go"))
		if err := os.Symlink(goBin, filepath.Join(prefix, "bin", "go")); err != nil {
			return err
		}
	}
	logDeps(logFile, "home_go_install_finish", map[string]any{"go": goBin})
	return nil
}

func downloadFile(url, dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	client := http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, resp.Body)
	return err
}

func extractGoArchive(archive, destDir string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		clean := filepath.Clean(h.Name)
		if clean == "." || strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
			return fmt.Errorf("unsafe archive path %q", h.Name)
		}
		path := filepath.Join(destDir, clean)
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(path, os.FileMode(h.Mode)); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(h.Mode))
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(out, tr)
			closeErr := out.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return err
			}
			_ = os.Remove(path)
			if err := os.Symlink(h.Linkname, path); err != nil {
				return err
			}
		}
	}
	return nil
}

func runDepsCommands(commands [][]string, logFile string) error {
	for _, argv := range commands {
		if len(argv) == 0 {
			continue
		}
		start := time.Now()
		logDeps(logFile, "command_start", map[string]any{"command": argv})
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		err := cmd.Run()
		exit := 0
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				exit = ee.ExitCode()
			} else {
				exit = 1
			}
		}
		logDeps(logFile, "command_finish", map[string]any{"command": argv, "exit_code": exit, "duration_sec": time.Since(start).Seconds()})
		if err != nil {
			return err
		}
	}
	return nil
}

func classifyDeps(statuses []DepsStatus) (installed, missing, unknown []string) {
	for _, st := range statuses {
		switch st.State {
		case "installed":
			installed = append(installed, st.Package)
		case "unknown":
			unknown = append(unknown, st.Package)
		default:
			missing = append(missing, st.Package)
		}
	}
	return
}

func depsStatusSummary(statuses []DepsStatus) map[string]int {
	if statuses == nil {
		return nil
	}
	m := map[string]int{"installed": 0, "missing": 0, "unknown": 0, "total": len(statuses)}
	for _, st := range statuses {
		if _, ok := m[st.State]; ok {
			m[st.State]++
		}
	}
	return m
}

func selectDepsPackages(packages []string, statuses []DepsStatus, missing, unknown []string, replace, force, onlyMissing bool) []string {
	if replace || force || statuses == nil || !onlyMissing {
		return append([]string(nil), packages...)
	}
	return dedupeStrings(append(append([]string{}, missing...), unknown...))
}

func depsSafeguards(method string, selected []string, inspect bool, opts depsOptions, onlyMissing bool) []string {
	var s []string
	if method == "home" {
		s = append(s, "default home method writes only under the selected home prefix")
		if unsupported := unsupportedHomePackages(selected); len(unsupported) > 0 {
			s = append(s, "these tools must already exist on PATH or be installed by an operator: "+strings.Join(unsupported, ", "))
		}
	}
	if opts.force {
		s = append(s, "force requested; install requires --confirm-force")
	}
	if opts.replace {
		s = append(s, "replace requested; commands intentionally target selected package set")
	}
	if inspect && len(selected) == 0 && onlyMissing {
		s = append(s, "all inspected packages are already installed; no install command generated")
	}
	return s
}

func depsRequiresPrivilege(manager string) bool {
	if _, ok := depsLinux[manager]; ok {
		return true
	}
	if _, ok := depsBSD[manager]; ok {
		return true
	}
	if _, ok := depsAIX[manager]; ok {
		return true
	}
	_, win := depsWindows[manager]
	return win
}

func detectDepsPackageManager(requested string) (string, string) {
	if requested != "" {
		if _, ok := depsLinux[requested]; ok {
			return "linux", requested
		}
		if _, ok := depsMacOS[requested]; ok {
			return "darwin", requested
		}
		if _, ok := depsWindows[requested]; ok {
			return "windows", requested
		}
		if _, ok := depsBSD[requested]; ok {
			if requested == "pkg" {
				return "freebsd", requested
			}
			return "openbsd", requested
		}
		if _, ok := depsAIX[requested]; ok {
			return "aix", requested
		}
		return runtime.GOOS, requested
	}
	sys := runtime.GOOS
	if sys == "linux" {
		for _, m := range []string{"apt", "dnf", "yum", "zypper", "pacman", "apk"} {
			b := m
			if m == "apt" {
				b = "apt-get"
			}
			if _, err := exec.LookPath(b); err == nil {
				return sys, m
			}
		}
	}
	if sys == "darwin" {
		return sys, "brew"
	}
	if sys == "windows" {
		if _, err := exec.LookPath("winget"); err == nil {
			return sys, "winget"
		}
		return sys, "choco"
	}
	if sys == "freebsd" {
		return sys, "pkg"
	}
	if sys == "openbsd" || sys == "netbsd" {
		return sys, "pkg_add"
	}
	if sys == "aix" {
		return sys, "installp"
	}
	return sys, "unknown"
}

func printDepsPlan(plan DepsPlan) {
	fmt.Printf("deps:   %s/%s\n", plan.InstallMethod, plan.PackageManager)
	fmt.Printf("prefix: %s\n", plan.HomePrefix)
	fmt.Printf("privileged: %v\n", plan.RequiresPrivilege)
	if plan.StatusSummary != nil {
		fmt.Printf("status: installed=%d missing=%d unknown=%d total=%d\n", plan.StatusSummary["installed"], plan.StatusSummary["missing"], plan.StatusSummary["unknown"], plan.StatusSummary["total"])
	}
	if len(plan.SelectedPackages) > 0 {
		fmt.Printf("selected: %s\n", strings.Join(plan.SelectedPackages, ", "))
	} else {
		fmt.Println("selected: none")
	}
	for _, s := range plan.Safeguards {
		fmt.Printf("note: %s\n", s)
	}
	if len(plan.Commands) > 0 {
		fmt.Println("commands:")
		for _, c := range plan.Commands {
			fmt.Printf("  %s\n", shellJoin(c))
		}
	}
}

func logDeps(path, event string, payload any) {
	if strings.TrimSpace(path) == "" {
		return
	}
	path = expandDepsHome(path)
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	rec := map[string]any{"ts": time.Now().UTC().Format(time.RFC3339), "event": event, "payload": payload}
	b, _ := json.Marshal(rec)
	_, _ = f.Write(append(b, '\n'))
}

func defaultDepsLogPath() string {
	return filepath.Join(depsDefaultHomePrefix, "logs", "dependencies.jsonl")
}

func expandDepsHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			if p == "~" {
				return home
			}
			return filepath.Join(home, strings.TrimPrefix(p, "~/"))
		}
	}
	return filepath.Clean(p)
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
func containsLineFold(text, want string) bool {
	want = strings.ToLower(strings.TrimSpace(want))
	for _, l := range strings.Split(text, "\n") {
		if strings.ToLower(strings.TrimSpace(l)) == want {
			return true
		}
	}
	return false
}
