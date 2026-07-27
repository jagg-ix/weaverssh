package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"reflect"
	"strings"

	"weaverssh/apicontract"
)

func cmdAPIContract(args []string) int {
	if len(args) == 0 {
		printAPIContractUsage()
		return 2
	}
	switch args[0] {
	case "validate":
		return cmdAPIContractValidate(args[1:])
	case "lock":
		return cmdAPIContractLock(args[1:])
	case "compare":
		return cmdAPIContractCompare(args[1:])
	case "list":
		return cmdAPIContractList(args[1:])
	case "help", "-h", "--help":
		printAPIContractUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "api-contract: unknown command %q\n", args[0])
		printAPIContractUsage()
		return 2
	}
}

func printAPIContractUsage() {
	fmt.Fprintln(os.Stderr, `usage:
  wv api-contract validate --catalog CATALOG.json [--lock CONTRACTS.lock.json] [--json]
  wv api-contract lock --catalog CATALOG.json --output CONTRACTS.lock.json [--json]
  wv api-contract compare --previous OLD.lock.json --current NEW.lock.json [--json]
  wv api-contract list --catalog CATALOG.json [--json]

The catalog can reference OpenAPI 3.1, OpenRPC 1.x, AsyncAPI 3.x,
JSON Schema 2020-12, proto3 source, and protobuf descriptor sets.`)
}

func cmdAPIContractValidate(args []string) int {
	fs := flag.NewFlagSet("api-contract validate", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	catalogPath := fs.String("catalog", "", "API contract catalog")
	lockPath := fs.String("lock", "", "optional expected lock file")
	jsonOut := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || strings.TrimSpace(*catalogPath) == "" {
		fmt.Fprintln(os.Stderr, "usage: wv api-contract validate --catalog CATALOG.json [--lock LOCK.json] [--json]")
		return 2
	}
	catalog, lock, err := loadAndValidateContracts(*catalogPath)
	if err != nil {
		return apiContractError("validate", err)
	}
	locked := false
	if strings.TrimSpace(*lockPath) != "" {
		expected, err := loadAPIContractLock(*lockPath)
		if err != nil {
			return apiContractError("validate", err)
		}
		if !reflect.DeepEqual(expected, lock) {
			return apiContractError("validate", errors.New("catalog or contract files differ from the expected lock"))
		}
		locked = true
	}
	result := map[string]any{"catalog": catalog.Name, "revision": catalog.Revision, "contracts": len(lock.Contracts), "locked": locked, "lock": lock}
	if *jsonOut {
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			return apiContractError("validate", err)
		}
	} else {
		fmt.Printf("valid API catalog %s revision %s with %d contract(s)", catalog.Name, catalog.Revision, len(lock.Contracts))
		if locked {
			fmt.Print("; lock verified")
		}
		fmt.Println()
	}
	return 0
}

func cmdAPIContractLock(args []string) int {
	fs := flag.NewFlagSet("api-contract lock", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	catalogPath := fs.String("catalog", "", "API contract catalog")
	outputPath := fs.String("output", "", "new exclusive lock file")
	jsonOut := fs.Bool("json", false, "emit lock JSON to stdout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || strings.TrimSpace(*catalogPath) == "" || strings.TrimSpace(*outputPath) == "" {
		fmt.Fprintln(os.Stderr, "usage: wv api-contract lock --catalog CATALOG.json --output LOCK.json [--json]")
		return 2
	}
	_, lock, err := loadAndValidateContracts(*catalogPath)
	if err != nil {
		return apiContractError("lock", err)
	}
	file, err := os.OpenFile(strings.TrimSpace(*outputPath), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return apiContractError("lock", err)
	}
	encodeErr := apicontract.EncodeLock(file, lock)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(encodeErr, syncErr, closeErr); err != nil {
		_ = os.Remove(strings.TrimSpace(*outputPath))
		return apiContractError("lock", err)
	}
	if *jsonOut {
		if err := json.NewEncoder(os.Stdout).Encode(lock); err != nil {
			return apiContractError("lock", err)
		}
	} else {
		fmt.Printf("wrote API contract lock %s with %d contract(s)\n", *outputPath, len(lock.Contracts))
	}
	return 0
}

func cmdAPIContractCompare(args []string) int {
	fs := flag.NewFlagSet("api-contract compare", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	previousPath := fs.String("previous", "", "previous lock")
	currentPath := fs.String("current", "", "current lock")
	jsonOut := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || strings.TrimSpace(*previousPath) == "" || strings.TrimSpace(*currentPath) == "" {
		fmt.Fprintln(os.Stderr, "usage: wv api-contract compare --previous OLD.lock.json --current NEW.lock.json [--json]")
		return 2
	}
	previous, err := loadAPIContractLock(*previousPath)
	if err != nil {
		return apiContractError("compare", err)
	}
	current, err := loadAPIContractLock(*currentPath)
	if err != nil {
		return apiContractError("compare", err)
	}
	report, err := apicontract.CompareLocks(previous, current)
	if err != nil {
		return apiContractError("compare", err)
	}
	if *jsonOut {
		if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
			return apiContractError("compare", err)
		}
	} else {
		fmt.Printf("API compatibility compatible=%t changes=%d\n", report.Compatible, len(report.Changes))
		for _, change := range report.Changes {
			fmt.Printf("  %s: %s compatible=%t", change.ID, change.Type, change.Compatible)
			if change.Reason != "" {
				fmt.Printf(" (%s)", change.Reason)
			}
			fmt.Println()
		}
	}
	if !report.Compatible {
		return 1
	}
	return 0
}

func cmdAPIContractList(args []string) int {
	fs := flag.NewFlagSet("api-contract list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	catalogPath := fs.String("catalog", "", "API contract catalog")
	jsonOut := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || strings.TrimSpace(*catalogPath) == "" {
		fmt.Fprintln(os.Stderr, "usage: wv api-contract list --catalog CATALOG.json [--json]")
		return 2
	}
	catalog, lock, err := loadAndValidateContracts(*catalogPath)
	if err != nil {
		return apiContractError("list", err)
	}
	if *jsonOut {
		if err := json.NewEncoder(os.Stdout).Encode(lock); err != nil {
			return apiContractError("list", err)
		}
	} else {
		fmt.Printf("%s revision %s\n", catalog.Name, catalog.Revision)
		for _, contract := range lock.Contracts {
			fmt.Printf("  %s@%s kind=%s stability=%s compatibility=%s sha256=%s\n", contract.ID, contract.Version, contract.Kind, contract.Stability, contract.Compatibility, contract.SHA256)
		}
	}
	return 0
}

func loadAndValidateContracts(path string) (apicontract.Catalog, apicontract.Lock, error) {
	catalog, err := apicontract.LoadCatalogFile(path)
	if err != nil {
		return apicontract.Catalog{}, apicontract.Lock{}, err
	}
	lock, err := apicontract.NewRegistry().ValidateCatalog(context.Background(), catalog)
	return catalog, lock, err
}

func loadAPIContractLock(path string) (apicontract.Lock, error) {
	file, err := os.Open(strings.TrimSpace(path))
	if err != nil {
		return apicontract.Lock{}, err
	}
	defer file.Close()
	return apicontract.DecodeLock(file)
}

func apiContractError(operation string, err error) int {
	fmt.Fprintf(os.Stderr, "api-contract %s: %v\n", operation, err)
	return 1
}
