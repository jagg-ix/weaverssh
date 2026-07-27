package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"weaverssh/originruntime"
)

const EnvOriginRuntimeConfig = originruntime.EnvConfig

var defaultOriginRuntimePathEnvironment = []string{
	"WEAVERSSH_TRANSFER_EVENT_FILE",
	"WEAVERSSH_TRANSFER_INPUT_DATA_FILE",
	"WEAVERSSH_TRANSFER_RESULT_FILE",
	"WEAVERSSH_TRANSFER_OUTPUT_MANIFEST_FILE",
	"WEAVERSSH_TRANSFER_OUTPUT_REGISTRY_ROOT",
	"WEAVERSSH_TRANSFER_RECEIVED_FILE",
	"WEAVERSSH_TRANSFER_OUTPUT_DIR",
	"WEAVERSSH_TRANSFER_OUTPUT_FILE",
	"WEAVERSSH_TRANSFER_LOCAL_PATH",
}

type repeatedStringFlag []string

func (values *repeatedStringFlag) String() string { return strings.Join(*values, ",") }
func (values *repeatedStringFlag) Set(value string) error {
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			*values = append(*values, part)
		}
	}
	return nil
}

func cmdOriginRuntime(args []string) int {
	if len(args) == 0 {
		printOriginRuntimeUsage()
		return 2
	}
	switch args[0] {
	case "validate":
		return cmdOriginRuntimeValidate(args[1:])
	case "describe":
		return cmdOriginRuntimeDescribe(args[1:])
	case "map":
		return cmdOriginRuntimeMap(args[1:])
	case "exec":
		return cmdOriginRuntimeExec(args[1:])
	case "help", "-h", "--help":
		printOriginRuntimeUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "origin-runtime: unknown command %q\n", args[0])
		printOriginRuntimeUsage()
		return 2
	}
}

func printOriginRuntimeUsage() {
	fmt.Fprintln(os.Stderr, `usage:
  wv origin-runtime validate --config RUNTIME.json
  wv origin-runtime describe --config RUNTIME.json [--json]
  wv origin-runtime map --config RUNTIME.json --to-host PATH
  wv origin-runtime map --config RUNTIME.json --to-guest PATH
  wv origin-runtime exec --config RUNTIME.json [options] -- COMMAND [ARG...]

validate checks the strict configuration without contacting the runtime.
describe performs live native, WSL, Docker, Kubernetes, or VM resolution.
exec passes WEAVERSSH_* variables by default. Use --inherit-env to explicitly
pass the complete host environment into the guest runtime.`)
}

func originRuntimeConfigFlag(fs *flag.FlagSet) *string {
	return fs.String("config", strings.TrimSpace(os.Getenv(originruntime.EnvConfig)), "origin runtime JSON configuration")
}

func requireOriginRuntimeConfig(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errors.New("--config or WEAVERSSH_ORIGIN_RUNTIME_CONFIG is required")
	}
	return path, nil
}

func openOriginRuntime(path string) (*originruntime.Runtime, error) {
	path, err := requireOriginRuntimeConfig(path)
	if err != nil {
		return nil, err
	}
	return originruntime.OpenFile(context.Background(), path, nil, nil)
}

func cmdOriginRuntimeValidate(args []string) int {
	fs := flag.NewFlagSet("origin-runtime validate", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := originRuntimeConfigFlag(fs)
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return 2
	}
	path, err := requireOriginRuntimeConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "origin-runtime validate: %v\n", err)
		return 2
	}
	config, digest, err := originruntime.LoadConfigFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "origin-runtime validate: %v\n", err)
		return 1
	}
	fmt.Printf("valid origin runtime config %s kind=%s sha256=%s\n", config.Name, config.Kind, digest)
	return 0
}

func cmdOriginRuntimeDescribe(args []string) int {
	fs := flag.NewFlagSet("origin-runtime describe", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := originRuntimeConfigFlag(fs)
	jsonOut := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return 2
	}
	runtime, err := openOriginRuntime(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "origin-runtime describe: %v\n", err)
		return 1
	}
	descriptor := runtime.Descriptor()
	if *jsonOut {
		if err := json.NewEncoder(os.Stdout).Encode(descriptor); err != nil {
			fmt.Fprintf(os.Stderr, "origin-runtime describe: %v\n", err)
			return 1
		}
		return 0
	}
	payload, _ := json.MarshalIndent(descriptor, "", "  ")
	fmt.Println(string(payload))
	return 0
}

func cmdOriginRuntimeMap(args []string) int {
	fs := flag.NewFlagSet("origin-runtime map", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := originRuntimeConfigFlag(fs)
	toHost := fs.Bool("to-host", false, "translate a guest path to the origin host")
	toGuest := fs.Bool("to-guest", false, "translate an origin-host path to the guest")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 || *toHost == *toGuest {
		fmt.Fprintln(os.Stderr, "usage: wv origin-runtime map --config FILE (--to-host|--to-guest) PATH")
		return 2
	}
	runtime, err := openOriginRuntime(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "origin-runtime map: %v\n", err)
		return 1
	}
	var mapped string
	if *toHost {
		mapped, err = runtime.MapGuestToHost(fs.Arg(0))
	} else {
		mapped, err = runtime.MapHostToGuest(fs.Arg(0))
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "origin-runtime map: %v\n", err)
		return 1
	}
	fmt.Println(mapped)
	return 0
}

func cmdOriginRuntimeExec(args []string) int {
	fs := flag.NewFlagSet("origin-runtime exec", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := originRuntimeConfigFlag(fs)
	directory := fs.String("dir", "", "guest or mapped host working directory")
	inheritEnvironment := fs.Bool("inherit-env", false, "pass the complete host environment into the guest")
	maxOutput := fs.Int("max-output-bytes", originruntime.MaxCommandOutputBytes, "maximum captured stdout and stderr bytes each")
	var copyEnvironment repeatedStringFlag
	var setEnvironment repeatedStringFlag
	var translateEnvironment repeatedStringFlag
	fs.Var(&copyEnvironment, "env", "copy one host environment variable; repeat or use commas")
	fs.Var(&setEnvironment, "set-env", "set NAME=VALUE in the guest; repeat")
	fs.Var(&translateEnvironment, "translate-env", "require translation of a path-valued environment variable; repeat or use commas")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	command := fs.Args()
	if len(command) == 0 {
		fmt.Fprintln(os.Stderr, "usage: wv origin-runtime exec --config FILE [options] -- COMMAND [ARG...]")
		return 2
	}
	runtime, err := openOriginRuntime(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "origin-runtime exec: %v\n", err)
		return 1
	}
	environment, err := originRuntimeEnvironment(*inheritEnvironment, copyEnvironment, setEnvironment)
	if err != nil {
		fmt.Fprintf(os.Stderr, "origin-runtime exec: %v\n", err)
		return 2
	}
	descriptor := runtime.Descriptor()
	environment[originruntime.EnvKind] = string(descriptor.Kind)
	environment[originruntime.EnvID] = descriptor.RuntimeID
	explicitTranslations := make(map[string]struct{}, len(translateEnvironment))
	for _, name := range translateEnvironment {
		name = strings.TrimSpace(name)
		if !validOriginRuntimeEnvironmentName(name) {
			fmt.Fprintf(os.Stderr, "origin-runtime exec: invalid --translate-env name %q\n", name)
			return 2
		}
		explicitTranslations[name] = struct{}{}
	}
	translationNames := append([]string(nil), defaultOriginRuntimePathEnvironment...)
	translationNames = append(translationNames, translateEnvironment...)
	for _, name := range uniqueSortedStrings(translationNames) {
		value, exists := environment[name]
		if !exists || strings.TrimSpace(value) == "" || !filepath.IsAbs(value) {
			continue
		}
		mapped, mapErr := runtime.MapHostToGuest(value)
		if mapErr == nil {
			environment[name] = mapped
			continue
		}
		if _, required := explicitTranslations[name]; required {
			fmt.Fprintf(os.Stderr, "origin-runtime exec: translate %s: %v\n", name, mapErr)
			return 1
		}
		// Default WeaverSSH path variables are host-only when a runtime has no
		// corresponding path map. Do not expose misleading inaccessible paths.
		delete(environment, name)
	}
	preparedCommand := append([]string(nil), command...)
	if filepath.IsAbs(preparedCommand[0]) {
		if mapped, mapErr := runtime.MapHostToGuest(preparedCommand[0]); mapErr == nil {
			preparedCommand[0] = mapped
		}
	}
	preparedDirectory := strings.TrimSpace(*directory)
	if preparedDirectory != "" && filepath.IsAbs(preparedDirectory) {
		if mapped, mapErr := runtime.MapHostToGuest(preparedDirectory); mapErr == nil {
			preparedDirectory = mapped
		}
	}
	result, runErr := runtime.Exec(context.Background(), originruntime.ExecRequest{
		Command: preparedCommand, Environment: environment, Directory: preparedDirectory,
		InheritHostEnv: false, Stdin: os.Stdin, MaxOutputBytes: *maxOutput,
	})
	_, _ = os.Stdout.Write(result.Stdout)
	_, _ = os.Stderr.Write(result.Stderr)
	if runErr != nil {
		fmt.Fprintf(os.Stderr, "origin-runtime exec: %v\n", runErr)
		if result.ExitCode > 0 && result.ExitCode <= 125 {
			return result.ExitCode
		}
		return 1
	}
	return 0
}

func originRuntimeEnvironment(inherit bool, copyNames, assignments []string) (map[string]string, error) {
	values := map[string]string{}
	for _, entry := range os.Environ() {
		name, value, ok := strings.Cut(entry, "=")
		if !ok || !validOriginRuntimeEnvironmentName(name) || strings.ContainsAny(value, "\x00\r\n") {
			continue
		}
		if inherit || strings.HasPrefix(name, "WEAVERSSH_") && name != originruntime.EnvConfig {
			values[name] = value
		}
	}
	for _, name := range copyNames {
		name = strings.TrimSpace(name)
		if !validOriginRuntimeEnvironmentName(name) {
			return nil, fmt.Errorf("invalid --env name %q", name)
		}
		if value, exists := os.LookupEnv(name); exists {
			if strings.ContainsAny(value, "\x00\r\n") {
				return nil, fmt.Errorf("invalid value for --env %s", name)
			}
			values[name] = value
		}
	}
	for _, assignment := range assignments {
		name, value, ok := strings.Cut(assignment, "=")
		name = strings.TrimSpace(name)
		if !ok || !validOriginRuntimeEnvironmentName(name) || strings.ContainsAny(value, "\x00\r\n") {
			return nil, fmt.Errorf("invalid --set-env assignment %q", assignment)
		}
		values[name] = value
	}
	return values, nil
}

func validOriginRuntimeEnvironmentName(value string) bool {
	if value == "" || len(value) > 128 || strings.Contains(value, "=") {
		return false
	}
	for index, char := range value {
		if !(char == '_' || char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z' || index > 0 && char >= '0' && char <= '9') {
			return false
		}
	}
	return true
}

func uniqueSortedStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
