package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"weaverssh/authproof"
	"weaverssh/hopproof"
	"weaverssh/originruntime"
)

const (
	// EnvWVOrigin contains the concrete signed node ID of the immediate previous
	// SSH/weaverssh hop. Each recursive session-host replaces it with its own node.
	EnvWVOrigin = "WVORIGIN"
	// EnvWVHop contains the base64url-encoded, SSHSIG-authenticated hop chain.
	EnvWVHop = "WVHOP"
)

// SignedWVOrigin returns the current concrete node ID. When this node starts the
// next SSH hop, it becomes that child's immediate WVORIGIN.
func SignedWVOrigin(ctx authproof.NodeContext) (string, error) {
	ctx = ctx.Normalized()
	if err := ctx.Validate(); err != nil {
		return "", err
	}
	current := strings.TrimSpace(ctx.CurrentNode)
	if err := validateSSHEnvironmentValue(current); err != nil {
		return "", fmt.Errorf("wvorigin: invalid current node ID: %w", err)
	}
	return current, nil
}

// ValidateWVOrigin verifies the immediate previous-node value received through
// SSH against the signed topology. Missing or mismatched values fail closed.
func ValidateWVOrigin(value string, ctx authproof.NodeContext) (string, error) {
	want, err := hopproof.PreviousNode(ctx)
	if err != nil {
		return "", err
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("%s was not received from SSH; configure sshd AcceptEnv %s %s or pass --wvorigin %s", EnvWVOrigin, EnvWVOrigin, EnvWVHop, want)
	}
	if value != want {
		return "", fmt.Errorf("%s=%q does not match signed previous node %q", EnvWVOrigin, value, want)
	}
	return value, nil
}

// injectOpenSSHSetEnv is the single-variable compatibility wrapper.
func injectOpenSSHSetEnv(commandArgs []string, value string) ([]string, bool, error) {
	return injectOpenSSHEnvironment(commandArgs, map[string]string{EnvWVOrigin: value}, false)
}

// injectOpenSSHEnvironment inserts authoritative SetEnv values into a direct
// OpenSSH invocation and optionally enables agent forwarding. Non-SSH child
// commands are returned unchanged so wrappers must forward values explicitly.
func injectOpenSSHEnvironment(commandArgs []string, environment map[string]string, forwardAgent bool) ([]string, bool, error) {
	if len(commandArgs) == 0 {
		return nil, false, nil
	}
	base := strings.ToLower(filepath.Base(commandArgs[0]))
	if base != "ssh" && base != "ssh.exe" {
		return append([]string(nil), commandArgs...), false, nil
	}

	authoritative := make(map[string]string, len(environment)+2)
	for name, value := range environment {
		authoritative[name] = value
	}
	for _, name := range []string{originruntime.EnvKind, originruntime.EnvID} {
		value := strings.TrimSpace(os.Getenv(name))
		if value == "" {
			continue
		}
		if existing, found := authoritative[name]; found && existing != value {
			return nil, false, fmt.Errorf("conflicting authoritative environment for %s", name)
		}
		authoritative[name] = value
	}
	environment = authoritative

	names := make([]string, 0, len(environment))
	for name, value := range environment {
		name = strings.TrimSpace(name)
		if name == "" || strings.ContainsAny(name, "=\x00\r\n\t ") {
			return nil, false, fmt.Errorf("invalid OpenSSH environment name %q", name)
		}
		if err := validateSSHEnvironmentValue(value); err != nil {
			return nil, false, fmt.Errorf("invalid %s value: %w", name, err)
		}
		names = append(names, name)
	}
	sort.Strings(names)
	found := make(map[string]bool, len(names))
	agentEnabled := false
	agentDisabled := false

	for index := 1; index < len(commandArgs); index++ {
		argument := commandArgs[index]
		switch argument {
		case "-A":
			agentEnabled = true
		case "-a":
			agentDisabled = true
		}
		option := ""
		switch {
		case argument == "-o" && index+1 < len(commandArgs):
			option = commandArgs[index+1]
			index++
		case strings.HasPrefix(argument, "-o") && len(argument) > 2:
			option = argument[2:]
		}
		option = strings.TrimSpace(option)
		lower := strings.ToLower(option)
		if strings.HasPrefix(lower, "forwardagent=") {
			value := strings.TrimSpace(lower[len("forwardagent="):])
			switch value {
			case "yes", "true":
				agentEnabled = true
			case "no", "false":
				agentDisabled = true
			}
		}
		if !strings.HasPrefix(lower, "setenv=") {
			continue
		}
		assignments := strings.Fields(option[len("SetEnv="):])
		for _, existing := range assignments {
			separator := strings.IndexByte(existing, '=')
			if separator <= 0 {
				continue
			}
			name, value := existing[:separator], existing[separator+1:]
			want, tracked := environment[name]
			if !tracked {
				continue
			}
			if value != want {
				return nil, false, fmt.Errorf("conflicting OpenSSH SetEnv for %s", name)
			}
			found[name] = true
		}
	}
	if forwardAgent && agentDisabled {
		return nil, false, errors.New("recursive session requires agent forwarding but ssh arguments disable it")
	}

	prefix := []string{commandArgs[0]}
	if forwardAgent && !agentEnabled {
		prefix = append(prefix, "-A")
	}
	var missing []string
	for _, name := range names {
		if !found[name] {
			missing = append(missing, name+"="+environment[name])
		}
	}
	if len(missing) > 0 {
		prefix = append(prefix, "-o", "SetEnv="+strings.Join(missing, " "))
	}
	out := make([]string, 0, len(prefix)+len(commandArgs)-1)
	out = append(out, prefix...)
	out = append(out, commandArgs[1:]...)
	return out, true, nil
}

func validateSSHEnvironmentValue(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("empty environment value")
	}
	if strings.ContainsAny(value, "=\x00\r\n\t ") {
		return errors.New("environment value contains whitespace or a reserved character")
	}
	return nil
}
