package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"sshwb/contract"
)

type caseInput struct {
	ID       string `json:"id"`
	Platform string `json:"platform"`
	HostSpec string `json:"host_spec"`
	User     string `json:"user"`
}

type inputPayload struct {
	Cases []caseInput `json:"cases"`
}

type caseOutput struct {
	ID                 string `json:"id"`
	NormalizedPlatform string `json:"normalized_platform"`
	Label              string `json:"label"`
	Host               string `json:"host"`
	User               string `json:"user"`
	Target             string `json:"target"`
	OK                 bool   `json:"ok"`
	Error              string `json:"error"`
}

type outputPayload struct {
	Cases []caseOutput `json:"cases"`
}

func evaluate(c caseInput) caseOutput {
	out := caseOutput{
		ID:                 c.ID,
		NormalizedPlatform: contract.NormalizeRemotePlatform(c.Platform),
		User:               contract.NormalizeUser(c.User),
	}
	label, host, err := contract.ParseHostSpec(c.HostSpec)
	if err != nil {
		out.OK = false
		out.Error = err.Error()
		return out
	}
	target, err := contract.BuildTarget(out.User, host)
	if err != nil {
		out.OK = false
		out.Error = err.Error()
		return out
	}
	out.OK = true
	out.Label = label
	out.Host = host
	out.Target = target
	return out
}

func main() {
	inputPath := flag.String("input", "", "path to contract input JSON")
	flag.Parse()
	if *inputPath == "" {
		fmt.Fprintln(os.Stderr, "--input is required")
		os.Exit(2)
	}
	raw, err := os.ReadFile(*inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read input: %v\n", err)
		os.Exit(2)
	}
	var in inputPayload
	if err := json.Unmarshal(raw, &in); err != nil {
		fmt.Fprintf(os.Stderr, "parse input json: %v\n", err)
		os.Exit(2)
	}
	out := outputPayload{Cases: make([]caseOutput, 0, len(in.Cases))}
	for _, c := range in.Cases {
		out.Cases = append(out.Cases, evaluate(c))
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "encode output: %v\n", err)
		os.Exit(2)
	}
}
