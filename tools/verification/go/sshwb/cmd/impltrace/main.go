package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"sshwb/impltrace"
)

func main() {
	defaultRoot, _ := filepath.Abs("../../../..")
	repoRoot := flag.String("repo-root", defaultRoot, "path to the weaverssh runtime repository root")
	output := flag.String("output", "", "NDJSON output path; stdout is used when omitted")
	flag.Parse()

	records, err := impltrace.Emit(*repoRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "emit impl trace: %v\n", err)
		os.Exit(1)
	}
	if *output != "" {
		if err := impltrace.WriteNDJSON(*output, records); err != nil {
			fmt.Fprintf(os.Stderr, "write impl trace: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("output=%s\n", *output)
		fmt.Printf("record_count=%d\n", len(records))
		return
	}
	for _, rec := range records {
		line, err := jsonMarshal(rec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "encode impl trace: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(line)
	}
}

func jsonMarshal(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
