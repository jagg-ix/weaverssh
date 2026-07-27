package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"weaverssh/internal/compat"
)

func cmdCompat(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "list", "kinds", "capabilities":
			return cmdCompatList(args[1:])
		case "check", "validate", "profile":
			return cmdCompatCheck(args[1:])
		case "help", "-h", "--help":
			printCompatHelp()
			return 0
		}
		if compat.KnownKind(args[0]) {
			return cmdCompatCheck(append([]string{"--kind", args[0]}, args[1:]...))
		}
		if strings.HasPrefix(args[0], "-") {
			return cmdCompatCheck(args)
		}
		fmt.Fprintf(os.Stderr, "compat: unknown command %q\n", args[0])
		printCompatHelp()
		return 2
	}
	printCompatHelp()
	return 2
}

func cmdCompatList(args []string) int {
	fs := flag.NewFlagSet("compat list", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv compat list [--json]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	kinds := compat.SupportedKinds()
	if *jsonOut {
		return printJSON(map[string]any{"version": compat.Version, "kinds": kinds})
	}
	fmt.Println("Compatibility adapters:")
	for _, kind := range kinds {
		fmt.Printf("  %s\n", kind)
	}
	fmt.Println()
	fmt.Println("These adapters integrate external protocols around weaverssh workflows; they do not replace the SSH/X11/WebSocket data plane.")
	return 0
}

func cmdCompatCheck(args []string) int {
	fs := flag.NewFlagSet("compat", flag.ContinueOnError)
	kind := fs.String("kind", "", "adapter kind: s3, https-tls, mqtt, hadoop")
	endpoint := fs.String("endpoint", "", "adapter endpoint URI")
	name := fs.String("name", "", "profile name")
	authRef := fs.String("auth-ref", "", "external credential reference; never a secret value")
	region := fs.String("region", "", "region hint for object-store/cloud adapters")
	jsonOut := fs.Bool("json", false, "emit JSON")
	metadata := keyValueFlags{}
	fs.Var(&metadata, "metadata", "metadata key=value; repeatable")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv compat --kind KIND --endpoint URI [--name NAME] [--auth-ref REF] [--region REGION] [--metadata k=v] [--json]")
		fmt.Fprintln(os.Stderr, "       wv compat KIND --endpoint URI [options]")
		fmt.Fprintln(os.Stderr, "       wv compat check --kind KIND --endpoint URI [options]")
		fmt.Fprintln(os.Stderr, "examples:")
		fmt.Fprintln(os.Stderr, "  wv compat --kind s3 --endpoint s3://bucket/prefix --region us-east-1")
		fmt.Fprintln(os.Stderr, "  wv compat https --endpoint https://api.example.com/hook")
		fmt.Fprintln(os.Stderr, "  wv compat mqtt --endpoint mqtts://broker.example.com:8883")
		fmt.Fprintln(os.Stderr, "  wv compat hadoop --endpoint hdfs://namenode:8020/data")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	p := compat.Profile{
		Name:     *name,
		Kind:     *kind,
		Endpoint: *endpoint,
		AuthRef:  *authRef,
		Region:   *region,
		Metadata: metadata.values,
	}
	profile, err := p.Plan()
	if err != nil {
		fmt.Fprintf(os.Stderr, "compat: %v\n", err)
		return 2
	}
	if *jsonOut {
		return printJSON(profile)
	}
	printCompatProfile(profile)
	return 0
}

func printCompatProfile(profile compat.Plan) {
	fmt.Printf("compatibility: %s\n", profile.Name)
	fmt.Printf("kind:          %s\n", profile.Kind)
	fmt.Printf("endpoint:      %s\n", profile.Endpoint)
	fmt.Printf("scheme:        %s\n", profile.Scheme)
	fmt.Printf("data-plane:    %s\n", profile.DataPlaneOwner)
	fmt.Printf("tls-required:  %t\n", profile.TLSRequired)
	if profile.LoopbackOnly {
		fmt.Println("loopback-only: true")
	}
	if len(profile.Capabilities) > 0 {
		fmt.Println("capabilities:")
		for _, c := range profile.Capabilities {
			fmt.Printf("  - %s\n", c)
		}
	}
	if len(profile.RequiredEnv) > 0 {
		fmt.Println("requirements:")
		for _, r := range profile.RequiredEnv {
			fmt.Printf("  - %s\n", r)
		}
	}
	if len(profile.ExampleCommands) > 0 {
		fmt.Println("commands:")
		for _, c := range profile.ExampleCommands {
			fmt.Printf("  %s\n", c)
		}
	}
	if len(profile.Notes) > 0 {
		fmt.Println("notes:")
		for _, n := range profile.Notes {
			fmt.Printf("  - %s\n", n)
		}
	}
}

func printCompatHelp() {
	fmt.Print(`wv compat — validate external protocol compatibility adapters

Usage:
  wv compat list [--json]
  wv compat --kind KIND --endpoint URI [options]
  wv compat KIND --endpoint URI [options]
  wv compat check --kind KIND --endpoint URI [options]

Supported kinds:
  s3          S3-compatible object storage import/export adapter
  https-tls   HTTPS/TLS webhook, artifact, or control edge adapter
  mqtt        MQTT event bus adapter; mqtts:// required off loopback
  hadoop      Hadoop/HDFS or WebHDFS storage import/export adapter

Compatibility adapters are adjuncts around weaverssh. They do not replace the
SSH/X11/WebSocket path, node-context authorization, or policy gates.
`)
}

type keyValueFlags struct {
	values map[string]string
}

func (f *keyValueFlags) String() string {
	if len(f.values) == 0 {
		return ""
	}
	parts := make([]string, 0, len(f.values))
	for k, v := range f.values {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, ",")
}

func (f *keyValueFlags) Set(raw string) error {
	key, value, ok := strings.Cut(raw, "=")
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	if !ok || key == "" {
		return fmt.Errorf("metadata must be key=value")
	}
	if f.values == nil {
		f.values = map[string]string{}
	}
	f.values[key] = value
	return nil
}
