package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"weaverssh/evidencebinding"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	switch args[0] {
	case "anchor":
		return runAnchor(args[1:])
	case "verify":
		return runVerify(args[1:])
	case "help", "-h", "--help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", args[0])
		usage()
		return 2
	}
}

func runAnchor(args []string) int {
	fs := flag.NewFlagSet("anchor", flag.ContinueOnError)
	configPath := fs.String("config", "", "provider configuration JSON")
	headPath := fs.String("head", "", "verified evidence head JSON")
	outputPath := fs.String("out", "", "receipt output JSON; stdout when empty")
	timeout := fs.Duration("timeout", 45*time.Second, "overall provider timeout")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || strings.TrimSpace(*configPath) == "" || strings.TrimSpace(*headPath) == "" {
		fmt.Fprintln(os.Stderr, "usage: wv-evidence-anchor anchor --config providers.json --head head.json [--out receipts.json]")
		return 2
	}
	inputs, err := loadInputs(*configPath, *headPath, *timeout)
	if err != nil {
		return fail(err)
	}
	defer inputs.Close()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	receipts, err := inputs.Policy.Anchor(ctx, inputs.Head)
	if err != nil {
		return fail(err)
	}
	return writeJSON(*outputPath, receipts)
}

func runVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	configPath := fs.String("config", "", "provider configuration JSON")
	headPath := fs.String("head", "", "verified evidence head JSON")
	receiptsPath := fs.String("receipts", "", "anchor receipts JSON")
	timeout := fs.Duration("timeout", 45*time.Second, "overall provider timeout")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || strings.TrimSpace(*configPath) == "" || strings.TrimSpace(*headPath) == "" || strings.TrimSpace(*receiptsPath) == "" {
		fmt.Fprintln(os.Stderr, "usage: wv-evidence-anchor verify --config providers.json --head head.json --receipts receipts.json")
		return 2
	}
	inputs, err := loadInputs(*configPath, *headPath, *timeout)
	if err != nil {
		return fail(err)
	}
	defer inputs.Close()
	var receipts []evidencebinding.AnchorReceipt
	if err := readStrictFile(*receiptsPath, &receipts); err != nil {
		return fail(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	report, err := inputs.Policy.Verify(ctx, inputs.Head, receipts)
	if err != nil {
		_ = json.NewEncoder(os.Stdout).Encode(report)
		return fail(err)
	}
	return writeJSON("", report)
}

type loadedInputs struct {
	Config    evidencebinding.AnchorProviderConfigFile
	Providers []evidencebinding.AnchorProvider
	Policy    evidencebinding.AnchorThresholdPolicy
	Head      evidencebinding.Head
}

func (i loadedInputs) Close() error { return evidencebinding.CloseAnchorProviders(i.Providers) }

func loadInputs(configPath, headPath string, timeout time.Duration) (loadedInputs, error) {
	config, err := evidencebinding.LoadAnchorProviderConfig(configPath)
	if err != nil {
		return loadedInputs{}, err
	}
	client := &http.Client{Timeout: timeout}
	providers, policy, err := config.Build(client, os.Getenv)
	if err != nil {
		return loadedInputs{}, err
	}
	fail := func(err error) (loadedInputs, error) {
		return loadedInputs{}, errors.Join(err, evidencebinding.CloseAnchorProviders(providers))
	}
	var head evidencebinding.Head
	if err := readStrictFile(headPath, &head); err != nil {
		return fail(err)
	}
	if _, err := evidencebinding.NewAnchorStatement(head); err != nil {
		return fail(err)
	}
	return loadedInputs{Config: config, Providers: providers, Policy: policy, Head: head}, nil
}

func readStrictFile(path string, destination any) error {
	data, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func writeJSON(path string, value any) int {
	var output io.Writer = os.Stdout
	var file *os.File
	var err error
	if strings.TrimSpace(path) != "" {
		file, err = os.OpenFile(strings.TrimSpace(path), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fail(err)
		}
		defer file.Close()
		output = file
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return fail(err)
	}
	return 0
}

func fail(err error) int {
	fmt.Fprintln(os.Stderr, "wv-evidence-anchor:", err)
	return 1
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: wv-evidence-anchor <anchor|verify> [flags]")
}
