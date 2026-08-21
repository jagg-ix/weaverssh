package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"weaverssh/containerstream"
)

func containsContainerStreamURI(args []string) bool {
	for _, arg := range args {
		if strings.HasPrefix(strings.TrimSpace(arg), containerstream.SchemePrefix) {
			return true
		}
	}
	return false
}

func cmdContainerStreamCat(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cat", flag.ContinueOnError)
	fs.SetOutput(stderr)
	provider := fs.String("provider", strings.TrimSpace(os.Getenv(containerstream.EnvProvider)), "orchestration provider override")
	mode := fs.String("discovery-mode", environmentDefault(containerstream.EnvDiscoveryMode, string(containerstream.ModeLocked)), "locked or per-request")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: wv cat [--provider NAME] [--discovery-mode locked|per-request] vfs://container/ENDPOINT/TARGET/PATH")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	request, err := containerstream.ParseURI(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "wv cat: %v\n", err)
		return 2
	}
	if strings.TrimSpace(*provider) != "" {
		request.ProviderHint = strings.TrimSpace(*provider)
	}
	registry := containerstream.NewDefaultRegistry(nil)
	router, err := containerstream.NewRouter(
		registry,
		containerstream.Discoverer{Probe: containerstream.OSProbe{}, Registry: registry},
		containerstream.RouterConfig{Mode: containerstream.DiscoveryMode(*mode)},
	)
	if err != nil {
		fmt.Fprintf(stderr, "wv cat: %v\n", err)
		return 2
	}
	stream, err := router.Open(context.Background(), request)
	if err != nil {
		fmt.Fprintf(stderr, "wv cat: %v\n", err)
		return 1
	}
	defer stream.Close()
	if _, err := io.Copy(stdout, stream); err != nil {
		fmt.Fprintf(stderr, "wv cat: %v\n", err)
		return 1
	}
	return 0
}

func cmdContainerProvider(args []string) int {
	if len(args) == 0 {
		printContainerProviderHelp(os.Stderr)
		return 2
	}
	switch args[0] {
	case "discover", "status", "refresh":
		return cmdContainerProviderStatus(args[1:], os.Stdout, os.Stderr)
	case "cat", "open":
		return cmdContainerStreamCat(args[1:], os.Stdout, os.Stderr)
	case "help", "-h", "--help":
		printContainerProviderHelp(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "container-provider: unknown command %q\n", args[0])
		printContainerProviderHelp(os.Stderr)
		return 2
	}
}

func cmdContainerProviderStatus(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("container-provider status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "emit JSON")
	provider := fs.String("provider", strings.TrimSpace(os.Getenv(containerstream.EnvProvider)), "lock an explicitly registered provider")
	mode := fs.String("discovery-mode", environmentDefault(containerstream.EnvDiscoveryMode, string(containerstream.ModeLocked)), "locked or per-request")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: wv container-provider status [--provider NAME] [--json]")
		return 2
	}
	registry := containerstream.NewDefaultRegistry(nil)
	router, err := containerstream.NewRouter(
		registry,
		containerstream.Discoverer{Probe: containerstream.OSProbe{}, Registry: registry},
		containerstream.RouterConfig{Mode: containerstream.DiscoveryMode(*mode), Provider: *provider},
	)
	if err != nil {
		fmt.Fprintf(stderr, "container-provider: %v\n", err)
		return 2
	}
	discovery, err := router.Refresh()
	if *jsonOut {
		if encodeErr := json.NewEncoder(stdout).Encode(discovery); encodeErr != nil {
			fmt.Fprintf(stderr, "container-provider: %v\n", encodeErr)
			return 1
		}
	} else {
		selected := discovery.Selected
		if selected == "" {
			selected = "none"
		}
		fmt.Fprintf(stdout, "selected: %s\n", selected)
		for _, candidate := range discovery.Candidates {
			fmt.Fprintf(stdout, "%-12s score=%3d available=%t", candidate.Provider, candidate.Score, candidate.Available)
			for _, artifact := range candidate.Artifacts {
				fmt.Fprintf(stdout, " %s:%s(+%d)", artifact.Kind, artifact.Value, artifact.Weight)
			}
			fmt.Fprintln(stdout)
		}
	}
	if err != nil && !errors.Is(err, containerstream.ErrNoProvider) {
		fmt.Fprintf(stderr, "container-provider: %v\n", err)
		return 1
	}
	if errors.Is(err, containerstream.ErrNoProvider) {
		fmt.Fprintln(stderr, "container-provider: no usable provider; install/configure an adapter CLI or set an explicit registered provider")
		return 1
	}
	return 0
}

func environmentDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func printContainerProviderHelp(writer io.Writer) {
	fmt.Fprint(writer, `wv container-provider - discover and route orchestration streams

Usage:
  wv container-provider status [--provider NAME] [--json]
  wv container-provider discover [--json]
  wv container-provider refresh [--json]
  wv container-provider cat vfs://container/ENDPOINT/TARGET/PATH

Built-in providers: kubernetes, rancher, cri, docker, podman, nomad.
Discovery locks one provider for the router/agent lifetime by default. Set
WEAVERSSH_CONTAINER_DISCOVERY_MODE=per-request for dynamic re-probing, or use
?provider=NAME on a URI for one request. Socket artifacts improve discovery
scores; built-in transports use argv-only CLI execution and can be replaced by
application-registered API/socket fast paths.
`)
}
