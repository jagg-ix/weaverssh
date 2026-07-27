package main

import (
	"fmt"
	"os"
	"strings"

	"weaverssh/internal/app"
	"weaverssh/originruntime"
)

func runSessionHostWithOriginRuntime(args []string) {
	configPath, filtered, err := extractOriginRuntimeConfig(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "session-host: %v\n", err)
		os.Exit(2)
		return
	}
	if configPath == "" {
		// Runtime metadata is hop-local. Do not forward values received from the
		// previous SSH node when this node has no runtime of its own.
		_ = os.Unsetenv(originruntime.EnvKind)
		_ = os.Unsetenv(originruntime.EnvID)
		runApp("wv session-host", app.RunSessionHost, args)
		return
	}
	if containsSessionHostRoot(filtered) {
		fmt.Fprintln(os.Stderr, "session-host: --root and --origin-runtime-config are mutually exclusive")
		os.Exit(2)
		return
	}
	runtime, err := originruntime.OpenFile(nil, configPath, nil, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "session-host: resolve origin runtime: %v\n", err)
		os.Exit(1)
		return
	}
	descriptor := runtime.Descriptor()
	if !originruntime.HasCapability(descriptor, originruntime.CapabilityFilesystem) {
		fmt.Fprintln(os.Stderr, "session-host: origin runtime does not expose a host-visible filesystem")
		os.Exit(1)
		return
	}
	if descriptor.ReadOnly && explicitlyDisablesReadOnly(filtered) {
		fmt.Fprintln(os.Stderr, "session-host: origin runtime is read-only but --read-only=false was requested")
		os.Exit(2)
		return
	}
	_ = os.Setenv(originruntime.EnvConfig, configPath)
	_ = os.Setenv(originruntime.EnvKind, string(descriptor.Kind))
	_ = os.Setenv(originruntime.EnvID, descriptor.RuntimeID)
	prepared := make([]string, 0, len(filtered)+2)
	prepared = append(prepared, "--root="+descriptor.HostRoot)
	if descriptor.ReadOnly {
		prepared = append(prepared, "--read-only=true")
	}
	prepared = append(prepared, filtered...)
	fmt.Fprintf(os.Stderr, "session-host: origin runtime kind=%s id=%s guest_root=%s host_root=%s read_only=%t\n", descriptor.Kind, descriptor.RuntimeID, descriptor.GuestRoot, descriptor.HostRoot, descriptor.ReadOnly)
	runApp("wv session-host", app.RunSessionHost, prepared)
}

func extractOriginRuntimeConfig(args []string) (string, []string, error) {
	configPath := strings.TrimSpace(os.Getenv(originruntime.EnvConfig))
	out := make([]string, 0, len(args))
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if argument == "--" {
			out = append(out, args[index:]...)
			break
		}
		switch {
		case argument == "--origin-runtime-config":
			if index+1 >= len(args) {
				return "", nil, fmt.Errorf("--origin-runtime-config requires a path")
			}
			index++
			value := strings.TrimSpace(args[index])
			if value == "" {
				return "", nil, fmt.Errorf("--origin-runtime-config requires a non-empty path")
			}
			if configPath != "" && configPath != value {
				return "", nil, fmt.Errorf("conflicting origin runtime configurations")
			}
			configPath = value
		case strings.HasPrefix(argument, "--origin-runtime-config="):
			value := strings.TrimSpace(strings.TrimPrefix(argument, "--origin-runtime-config="))
			if value == "" {
				return "", nil, fmt.Errorf("--origin-runtime-config requires a non-empty path")
			}
			if configPath != "" && configPath != value {
				return "", nil, fmt.Errorf("conflicting origin runtime configurations")
			}
			configPath = value
		default:
			out = append(out, argument)
		}
	}
	return configPath, out, nil
}

func containsSessionHostRoot(args []string) bool {
	for _, argument := range args {
		if argument == "--" {
			return false
		}
		if argument == "--root" || argument == "-root" || strings.HasPrefix(argument, "--root=") || strings.HasPrefix(argument, "-root=") {
			return true
		}
	}
	return false
}

func explicitlyDisablesReadOnly(args []string) bool {
	for index, argument := range args {
		if argument == "--" {
			return false
		}
		if argument == "--read-only=false" || argument == "-read-only=false" {
			return true
		}
		if (argument == "--read-only" || argument == "-read-only") && index+1 < len(args) && strings.EqualFold(strings.TrimSpace(args[index+1]), "false") {
			return true
		}
	}
	return false
}
