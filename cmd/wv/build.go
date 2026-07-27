package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// matrixScriptRel is the project's cross-platform build-matrix tool, reused here
// so `wv build` and `wv install` produce binaries for the maintained OS/arch
// matrix with the same hardened/PIE flags as packaging.
const matrixScriptRel = "tools/packaging/build_weaverssh_matrix.py"

// matrixScriptPath walks up from the cwd to locate the matrix builder inside a
// weaverssh checkout. Returns ("", false) when not run from a checkout.
func matrixScriptPath() (string, bool) {
	dir, err := os.Getwd()
	if err != nil {
		return "", false
	}
	for {
		p := filepath.Join(dir, matrixScriptRel)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

// matrixBuildOne builds the wv binary for a single GOOS/GOARCH target via the
// matrix builder and returns the path to the produced wv (or wv.exe).
func matrixBuildOne(script, target, buildDir string) (string, error) {
	if _, err := exec.LookPath("python3"); err != nil {
		return "", fmt.Errorf("python3 not found")
	}
	out, err := exec.Command("python3", script, "build", "--target", target, "--build-dir", buildDir).Output()
	if err != nil {
		return "", fmt.Errorf("matrix build %s: %w", target, err)
	}
	var res struct {
		OK      bool     `json:"ok"`
		Outputs []string `json:"outputs"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		return "", fmt.Errorf("parse matrix output for %s: %w", target, err)
	}
	for _, o := range res.Outputs {
		switch filepath.Base(o) {
		case "wv", "wv.exe":
			return o, nil
		}
	}
	return "", fmt.Errorf("matrix build produced no wv binary for %s", target)
}

// cmdBuild fronts the matrix builder so `wv build` can produce wv for a matrix
// of OS targets: `wv build --preset major` / `wv build --target linux/arm64`.
// With no flags it builds the default `major` preset. Args pass straight to the
// matrix builder's `build` command.
func cmdBuild(args []string) int {
	for _, a := range args {
		if a == "-h" || a == "--help" || a == "help" {
			fmt.Println("usage: wv build [--preset NAME ...] [--target GOOS/GOARCH ...] [--build-dir DIR] [--security-profile hardened|compat|debug]")
			fmt.Println("  Builds wv (and the rest of the suite) for a matrix of OS/arch targets.")
			fmt.Println("  Presets: major, linux-major, darwin-major, windows-major, freebsd-major, openbsd-major.")
			fmt.Println("  No flags builds the `major` preset. Must run from a weaverssh checkout.")
			return 0
		}
	}
	script, ok := matrixScriptPath()
	if !ok {
		fmt.Fprintf(os.Stderr, "wv build: run from a weaverssh checkout (%s not found)\n", matrixScriptRel)
		return 1
	}
	if _, err := exec.LookPath("python3"); err != nil {
		fmt.Fprintln(os.Stderr, "wv build: python3 is required")
		return 1
	}
	if err := runStdio("python3", append([]string{script, "build"}, args...)); err != nil {
		fmt.Fprintf(os.Stderr, "wv build: %v\n", err)
		return 1
	}
	return 0
}
