package connectionscan

// Config-source abstraction. Discovery does not have to read ~/.ssh/config from
// a fixed path: the ssh_config content can be supplied dynamically. A spec (from
// a --flag, env var, or .wv config) selects the source:
//
//	""            default discovery (~/.ssh/config, system config, Include/config.d)
//	/path, path:/p  a filesystem file
//	-             standard input
//	fd:N          an already-open file descriptor (e.g. from a parent process)
//	pipe:/p       a named pipe / FIFO, read once
//	exec:CMD      run CMD; its stdout is the ssh_config (a program or "library")
//
// Every non-default spec is read once into memory and parsed as one source, so a
// program, pipe, or descriptor can provide configuration that never lands on
// disk. A memory-mapped or in-process producer is reached the same way, via
// fd: or exec:.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// SSHConfigFromSpec resolves spec into parsed ssh client configs.
func SSHConfigFromSpec(spec string) ([]SSHClientConfig, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return DetectSSHClientConfigs(), nil
	}
	data, label, err := readConfigSpec(spec)
	if err != nil {
		return nil, err
	}
	blocks := parseSSHConfigData(data, label, SSHConfigSource{Index: 1, Path: label, Scope: "source", Reason: spec, Exists: true})
	entries := mergeAndFilterBlocks(blocks)
	return reindexSSHConfigs(entries), nil
}

// DiscoverFrom is Discover, but with ssh_config taken from spec (PuTTY and
// known_hosts detection are unchanged). An empty spec is exactly Discover().
func DiscoverFrom(spec string) (Result, error) {
	if strings.TrimSpace(spec) == "" {
		return Discover(), nil
	}
	entries, err := SSHConfigFromSpec(spec)
	if err != nil {
		return Result{}, err
	}
	res := Result{
		SSHClientConfigs: entries,
		PuTTYSessions:    DetectPuTTYSessionConfigs(),
		KnownHosts:       DetectKnownHosts(),
	}
	res.Profiles = mergeProfiles(res)
	return res, nil
}

// readConfigSpec fetches the raw bytes named by spec and a label for the source.
func readConfigSpec(spec string) ([]byte, string, error) {
	switch {
	case spec == "-":
		data, err := io.ReadAll(os.Stdin)
		return data, "<stdin>", err
	case strings.HasPrefix(spec, "fd:"):
		n, err := strconv.Atoi(strings.TrimPrefix(spec, "fd:"))
		if err != nil {
			return nil, "", fmt.Errorf("ssh-config source: invalid fd %q: %w", spec, err)
		}
		f := os.NewFile(uintptr(n), fmt.Sprintf("fd/%d", n))
		if f == nil {
			return nil, "", fmt.Errorf("ssh-config source: fd %d is not open", n)
		}
		data, err := io.ReadAll(f)
		return data, spec, err
	case strings.HasPrefix(spec, "pipe:"):
		p := cleanPath(strings.TrimPrefix(spec, "pipe:"))
		data, err := os.ReadFile(p)
		return data, p, err
	case strings.HasPrefix(spec, "exec:"):
		return runConfigProgram(strings.TrimPrefix(spec, "exec:"))
	case strings.HasPrefix(spec, "path:"):
		p := cleanPath(strings.TrimPrefix(spec, "path:"))
		data, err := os.ReadFile(p)
		return data, p, err
	default:
		p := cleanPath(spec)
		data, err := os.ReadFile(p)
		return data, p, err
	}
}

// runConfigProgram runs cmdline and returns its stdout as ssh_config content.
func runConfigProgram(cmdline string) ([]byte, string, error) {
	fields := strings.Fields(strings.TrimSpace(cmdline))
	if len(fields) == 0 {
		return nil, "", errors.New("ssh-config source: empty exec command")
	}
	out, err := exec.Command(fields[0], fields[1:]...).Output()
	if err != nil {
		return nil, "", fmt.Errorf("ssh-config source %q: %w", cmdline, err)
	}
	return out, "exec:" + fields[0], nil
}
