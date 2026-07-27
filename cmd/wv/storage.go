package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"weaverssh/storageadapter"
)

func cmdStorage(args []string) int {
	if len(args) == 0 {
		printStorageUsage()
		return 2
	}
	switch args[0] {
	case "engines", "providers":
		return cmdStorageEngines(args[1:])
	case "validate":
		return cmdStorageValidate(args[1:])
	case "status", "inspect":
		return cmdStorageStatus(args[1:])
	case "get":
		return cmdStorageGet(args[1:])
	case "put":
		return cmdStoragePut(args[1:])
	case "delete", "rm":
		return cmdStorageDelete(args[1:])
	case "scan", "list":
		return cmdStorageScan(args[1:])
	case "migrate", "copy":
		return cmdStorageMigrate(args[1:])
	case "help", "-h", "--help":
		printStorageUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "storage: unknown command %q\n", args[0])
		return 2
	}
}

func printStorageUsage() {
	fmt.Fprintln(os.Stderr, `usage:
  wv storage engines [--json]
  wv storage validate CONFIG.json [--json]
  wv storage status CONFIG.json [--json]
  wv storage get CONFIG.json --key KEY [--raw|--json]
  wv storage put CONFIG.json --key KEY (--value TEXT|--file PATH) [--expected TEXT]
  wv storage delete CONFIG.json --key KEY [--expected TEXT]
  wv storage scan CONFIG.json [--prefix PREFIX] [--after KEY] [--limit N] [--json]
  wv storage migrate --from SOURCE.json --to DESTINATION.json [--prefix PREFIX] [--replace]

The default binary includes memory and file engines. SQLite and RocksDB are
registered by builds using the sqlite or rocksdb tags.`)
}

func cmdStorageEngines(args []string) int {
	fs := flag.NewFlagSet("storage engines", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 { return 2 }
	engines := storageadapter.Engines()
	if *jsonOut { return printJSON(map[string]any{"version": storageadapter.ConfigVersion, "engines": engines}) }
	for _, engine := range engines { fmt.Println(engine) }
	return 0
}

func loadStorageConfigOperand(args []string, name string) (storageadapter.Config, []string, error) {
	leading, rest := splitLeadingOperands(args, 1)
	if len(leading) != 1 {
		return storageadapter.Config{}, nil, fmt.Errorf("%s requires CONFIG.json", name)
	}
	config, err := storageadapter.LoadConfigFile(leading[0])
	return config, rest, err
}

func cmdStorageValidate(args []string) int {
	config, rest, err := loadStorageConfigOperand(args, "storage validate")
	if err != nil { return storageError("validate", err) }
	fs := flag.NewFlagSet("storage validate", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(rest); err != nil || fs.NArg() != 0 { return 2 }
	available := false
	for _, engine := range storageadapter.Engines() { if engine == config.Engine { available = true } }
	result := map[string]any{"valid": true, "available": available, "config": config}
	if *jsonOut { return printJSON(result) }
	fmt.Printf("valid storage config engine=%s namespace=%s available=%t\n", config.Engine, config.Namespace, available)
	if !available { return 1 }
	return 0
}

func cmdStorageStatus(args []string) int {
	config, rest, err := loadStorageConfigOperand(args, "storage status")
	if err != nil { return storageError("status", err) }
	fs := flag.NewFlagSet("storage status", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON")
	timeout := fs.Duration("timeout", 10*time.Second, "open timeout")
	if err := fs.Parse(rest); err != nil || fs.NArg() != 0 || *timeout <= 0 { return 2 }
	ctx, cancel := context.WithTimeout(context.Background(), *timeout); defer cancel()
	store, err := storageadapter.Open(ctx, config)
	if err != nil { return storageError("status", err) }
	defer store.Close()
	snapshot := store.Snapshot()
	if *jsonOut { return printJSON(snapshot) }
	fmt.Printf("engine=%s namespace=%s entries=%d bytes=%d transactions=%t scan=%t durable=%t read-only=%t\n", snapshot.Engine, snapshot.Namespace, snapshot.Entries, snapshot.Bytes, snapshot.Capabilities.Transactions, snapshot.Capabilities.OrderedScan, snapshot.Capabilities.Durable, snapshot.Capabilities.ReadOnly)
	return 0
}

func cmdStorageGet(args []string) int {
	config, rest, err := loadStorageConfigOperand(args, "storage get")
	if err != nil { return storageError("get", err) }
	fs := flag.NewFlagSet("storage get", flag.ContinueOnError)
	key := fs.String("key", "", "UTF-8 key")
	raw := fs.Bool("raw", false, "write raw value")
	jsonOut := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(rest); err != nil || fs.NArg() != 0 || *key == "" || (*raw && *jsonOut) { return 2 }
	store, err := storageadapter.Open(context.Background(), config)
	if err != nil { return storageError("get", err) }
	defer store.Close()
	value, err := store.Get(context.Background(), []byte(*key))
	if err != nil { return storageError("get", err) }
	if *raw { _, err = os.Stdout.Write(value); if err != nil { return storageError("get", err) }; return 0 }
	if *jsonOut { return printJSON(map[string]any{"key": *key, "value_base64": base64.StdEncoding.EncodeToString(value), "bytes": len(value)}) }
	fmt.Println(string(value))
	return 0
}

func cmdStoragePut(args []string) int {
	config, rest, err := loadStorageConfigOperand(args, "storage put")
	if err != nil { return storageError("put", err) }
	fs := flag.NewFlagSet("storage put", flag.ContinueOnError)
	key := fs.String("key", "", "UTF-8 key")
	value := fs.String("value", "", "literal value")
	filePath := fs.String("file", "", "value file; - reads stdin")
	expected := fs.String("expected", "", "expected current value; empty means unconditional")
	if err := fs.Parse(rest); err != nil || fs.NArg() != 0 || *key == "" || (*value == "") == (*filePath == "") { return 2 }
	payload, err := readStorageValue(*value, *filePath, config.MaxValueBytes)
	if err != nil { return storageError("put", err) }
	store, err := storageadapter.Open(context.Background(), config)
	if err != nil { return storageError("put", err) }
	defer store.Close()
	err = store.Update(context.Background(), func(tx storageadapter.Tx) error {
		if *expected != "" { return tx.CompareAndSwap([]byte(*key), []byte(*expected), payload) }
		return tx.Put([]byte(*key), payload)
	})
	if err != nil { return storageError("put", err) }
	fmt.Printf("stored %d bytes at %s\n", len(payload), *key)
	return 0
}

func cmdStorageDelete(args []string) int {
	config, rest, err := loadStorageConfigOperand(args, "storage delete")
	if err != nil { return storageError("delete", err) }
	fs := flag.NewFlagSet("storage delete", flag.ContinueOnError)
	key := fs.String("key", "", "UTF-8 key")
	expected := fs.String("expected", "", "expected current value")
	if err := fs.Parse(rest); err != nil || fs.NArg() != 0 || *key == "" { return 2 }
	store, err := storageadapter.Open(context.Background(), config)
	if err != nil { return storageError("delete", err) }
	defer store.Close()
	err = store.Update(context.Background(), func(tx storageadapter.Tx) error {
		if *expected != "" { return tx.CompareAndSwap([]byte(*key), []byte(*expected), nil) }
		return tx.Delete([]byte(*key))
	})
	if err != nil { return storageError("delete", err) }
	fmt.Printf("deleted %s\n", *key)
	return 0
}

func cmdStorageScan(args []string) int {
	config, rest, err := loadStorageConfigOperand(args, "storage scan")
	if err != nil { return storageError("scan", err) }
	fs := flag.NewFlagSet("storage scan", flag.ContinueOnError)
	prefix := fs.String("prefix", "", "key prefix")
	after := fs.String("after", "", "exclusive key cursor")
	limit := fs.Int("limit", 100, "maximum entries")
	jsonOut := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(rest); err != nil || fs.NArg() != 0 || *limit <= 0 || *limit > 10000 { return 2 }
	store, err := storageadapter.Open(context.Background(), config)
	if err != nil { return storageError("scan", err) }
	defer store.Close()
	entries, err := store.Scan(context.Background(), storageadapter.ScanOptions{Prefix: []byte(*prefix), After: []byte(*after), Limit: *limit})
	if err != nil { return storageError("scan", err) }
	if *jsonOut {
		type item struct { Key string `json:"key"`; ValueBase64 string `json:"value_base64"`; Bytes int `json:"bytes"` }
		items := make([]item, 0, len(entries))
		for _, entry := range entries { items = append(items, item{Key: string(entry.Key), ValueBase64: base64.StdEncoding.EncodeToString(entry.Value), Bytes: len(entry.Value)}) }
		return printJSON(items)
	}
	for _, entry := range entries { fmt.Printf("%s\t%d\n", string(entry.Key), len(entry.Value)) }
	return 0
}

func cmdStorageMigrate(args []string) int {
	fs := flag.NewFlagSet("storage migrate", flag.ContinueOnError)
	fromPath := fs.String("from", "", "source config")
	toPath := fs.String("to", "", "destination config")
	prefix := fs.String("prefix", "", "key prefix")
	batch := fs.Int("batch", 256, "entries per transaction")
	replace := fs.Bool("replace", false, "replace destination keys")
	jsonOut := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *fromPath == "" || *toPath == "" || *batch <= 0 { return 2 }
	fromConfig, err := storageadapter.LoadConfigFile(*fromPath); if err != nil { return storageError("migrate", err) }
	toConfig, err := storageadapter.LoadConfigFile(*toPath); if err != nil { return storageError("migrate", err) }
	source, err := storageadapter.Open(context.Background(), fromConfig); if err != nil { return storageError("migrate", err) }
	defer source.Close()
	destination, err := storageadapter.Open(context.Background(), toConfig); if err != nil { return storageError("migrate", err) }
	defer destination.Close()
	report, err := storageadapter.Migrate(context.Background(), source, destination, storageadapter.MigrateOptions{Prefix: []byte(*prefix), BatchSize: *batch, Replace: *replace})
	if err != nil { return storageError("migrate", err) }
	if *jsonOut { return printJSON(report) }
	fmt.Printf("migrated %d entries (%d bytes) in %d batches from %s to %s\n", report.Entries, report.Bytes, report.Batches, report.SourceEngine, report.DestinationEngine)
	return 0
}

func readStorageValue(literal, path string, maximum int) ([]byte, error) {
	if path == "" { return []byte(literal), nil }
	var reader io.Reader
	var file *os.File
	if path == "-" { reader = os.Stdin } else {
		opened, err := os.Open(path); if err != nil { return nil, err }
		file = opened; defer file.Close(); reader = file
	}
	payload, err := io.ReadAll(io.LimitReader(reader, int64(maximum)+1))
	if err != nil { return nil, err }
	if len(payload) > maximum { return nil, errors.New("storage: value exceeds configured maximum") }
	return payload, nil
}

func storageError(action string, err error) int {
	fmt.Fprintf(os.Stderr, "storage %s: %v\n", action, err)
	return 1
}

var _ = json.RawMessage{}
