package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestDepsDefaultHomePlanDoesNotRequirePython(t *testing.T) {
	prefix := t.TempDir()
	plan := buildDepsPlan(depsOptions{command: "plan", method: "auto", homePrefix: prefix, includeBuild: true}, false)
	if plan.InstallMethod != "home" {
		t.Fatalf("InstallMethod = %q, want home", plan.InstallMethod)
	}
	if plan.PackageManager != "home" {
		t.Fatalf("PackageManager = %q, want home", plan.PackageManager)
	}
	if plan.RequiresPrivilege {
		t.Fatal("home plan should not require elevated privileges")
	}
	if !containsString(plan.Packages, "go") {
		t.Fatalf("include-build plan packages = %v, want go", plan.Packages)
	}
	if containsString(plan.Packages, "python3") || containsString(plan.Packages, "python") {
		t.Fatalf("native home dependency plan should not require Python: %v", plan.Packages)
	}
	for _, cmd := range plan.Commands {
		joined := strings.Join(cmd, " ")
		if strings.Contains(joined, "install_runtime_dependencies.py") {
			t.Fatalf("native dependency command should not call Python installer: %s", joined)
		}
	}
}

func TestDepsPackageManagerBuildPlanKeepsPythonAsDeveloperTooling(t *testing.T) {
	plan := buildDepsPlan(depsOptions{command: "plan", method: "package-manager", manager: "apt", homePrefix: t.TempDir(), includeBuild: true}, false)
	if plan.InstallMethod != "package-manager" {
		t.Fatalf("InstallMethod = %q, want package-manager", plan.InstallMethod)
	}
	if !containsString(plan.Packages, "python3") {
		t.Fatalf("apt include-build packages = %v, want python3 for developer/package tooling", plan.Packages)
	}
	if !containsString(plan.Packages, "golang") {
		t.Fatalf("apt include-build packages = %v, want golang", plan.Packages)
	}
}

func TestDepsStatusHomeJSONDoesNotInstall(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "deps.jsonl")
	if rc := cmdDeps([]string{"status", "--include-build", "--home-prefix", t.TempDir(), "--log-file", logFile, "--json"}); rc != 0 {
		t.Fatalf("cmdDeps status rc = %d, want 0", rc)
	}
}

func TestDepsInstallForceRequiresConfirm(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "deps.jsonl")
	rc := cmdDeps([]string{"install", "--force", "--home-prefix", t.TempDir(), "--log-file", logFile, "--json"})
	if rc != 2 {
		t.Fatalf("cmdDeps install --force rc = %d, want 2", rc)
	}
}

func TestDepsTopLevelCommandRegistered(t *testing.T) {
	if !containsString(topLevelCommands, "deps") {
		t.Fatalf("topLevelCommands missing deps: %v", topLevelCommands)
	}
	if !containsString(topLevelCommands, "dependencies") {
		t.Fatalf("topLevelCommands missing dependencies: %v", topLevelCommands)
	}
}

func TestDepsPackageManagerMatrixIncludesBSDAndAIX(t *testing.T) {
	cases := []struct {
		manager     string
		platform    string
		wantPkg     string
		wantCommand string
	}{
		{manager: "pkg", platform: "freebsd", wantPkg: "openssh-portable", wantCommand: "pkg install"},
		{manager: "pkg_add", platform: "openbsd", wantPkg: "xauth", wantCommand: "pkg_add"},
		{manager: "installp", platform: "aix", wantPkg: "openssh", wantCommand: "AIX installp requires approved local media"},
	}
	for _, tc := range cases {
		t.Run(tc.manager, func(t *testing.T) {
			plan := buildDepsPlan(depsOptions{command: "plan", method: "package-manager", manager: tc.manager, homePrefix: t.TempDir(), includeBuild: true, yes: true}, false)
			if plan.Platform != tc.platform {
				t.Fatalf("Platform = %q, want %q", plan.Platform, tc.platform)
			}
			if !containsString(plan.Packages, tc.wantPkg) {
				t.Fatalf("packages = %v, want %q", plan.Packages, tc.wantPkg)
			}
			joined := ""
			for _, cmd := range plan.Commands {
				joined += strings.Join(cmd, " ") + "\n"
			}
			if !strings.Contains(joined, tc.wantCommand) {
				t.Fatalf("commands = %q, want substring %q", joined, tc.wantCommand)
			}
		})
	}
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
