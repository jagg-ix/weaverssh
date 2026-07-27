package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

type chainListReport struct {
	StorePath string      `json:"store_path"`
	Active    string      `json:"active,omitempty"`
	Chains    []ConnChain `json:"chains"`
}

// cmdConnectionsDispatch preserves the existing connection-profile dispatcher
// while adding the stored-chain namespace without changing cmdConnections'
// compatibility behavior for direct node-sequence flags.
func cmdConnectionsDispatch(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "chain", "chains":
			return cmdChains(args[1:])
		}
	}
	return cmdConnections(args)
}

func cmdChains(args []string) int {
	if len(args) == 0 {
		return cmdChainList(nil)
	}
	switch args[0] {
	case "list", "ls":
		return cmdChainList(args[1:])
	case "set", "create", "update", "configure":
		return cmdChainSet(args[1:])
	case "show", "get":
		return cmdChainShow(args[1:])
	case "use", "select":
		return cmdChainUse(args[1:])
	case "current":
		return cmdChainCurrent(args[1:])
	case "remove", "delete", "rm":
		return cmdChainRemove(args[1:])
	case "rename", "mv":
		return cmdChainRename(args[1:])
	case "clear":
		return cmdChainClear(args[1:])
	case "help", "-h", "--help":
		printChainHelp()
		return 0
	default:
		if strings.HasPrefix(args[0], "-") {
			return cmdChainSet(args)
		}
		fmt.Fprintf(os.Stderr, "chain: unknown command %q\n", args[0])
		printChainHelp()
		return 2
	}
}

func cmdChainSet(args []string) int {
	leading, rest := splitLeadingName(args)
	if leading != "" {
		rest = append([]string{"--label", leading}, rest...)
	}
	return cmdConnectionsNodes(rest)
}

func cmdChainList(args []string) int {
	fs := flag.NewFlagSet("chain list", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv chain list [--json]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	store, err := loadConnStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "chain list: %v\n", err)
		return 1
	}
	chains := append([]ConnChain(nil), store.Chains...)
	sortChains(chains)
	if *jsonOut {
		return printJSON(chainListReport{StorePath: connectionsStorePath(), Active: store.ActiveChain, Chains: chains})
	}
	fmt.Printf("store: %s\n", connectionsStorePath())
	if len(chains) == 0 {
		fmt.Println("chains: none")
		return 0
	}
	fmt.Println("chains:")
	for _, chain := range chains {
		mark := " "
		if chain.Label == store.ActiveChain {
			mark = "*"
		}
		fmt.Printf("  %s #%d %-20s %s\n", mark, chain.Number, chain.Label, formatChainNodes(chain.Nodes))
	}
	return 0
}

func cmdChainShow(args []string) int {
	leading, rest := splitLeadingName(args)
	fs := flag.NewFlagSet("chain show", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv chain show [LABEL|NUMBER] [--json]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	ref := leading
	if ref == "" && fs.NArg() == 1 {
		ref = fs.Arg(0)
	} else if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	store, err := loadConnStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "chain show: %v\n", err)
		return 1
	}
	chain, _, ok := resolveChain(store, ref)
	if !ok {
		if strings.TrimSpace(ref) == "" {
			fmt.Fprintln(os.Stderr, "chain show: no active chain")
		} else {
			fmt.Fprintf(os.Stderr, "chain show: chain %q not found\n", ref)
		}
		return 1
	}
	if *jsonOut {
		return printJSON(chain)
	}
	printChain(chain, chain.Label == store.ActiveChain)
	return 0
}

func cmdChainUse(args []string) int {
	fs := flag.NewFlagSet("chain use", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv chain use LABEL|NUMBER [--json]")
		fs.PrintDefaults()
	}
	leading, rest := splitLeadingName(args)
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	ref := leading
	if ref == "" && fs.NArg() == 1 {
		ref = fs.Arg(0)
	} else if fs.NArg() != 0 || strings.TrimSpace(ref) == "" {
		fs.Usage()
		return 2
	}
	store, err := loadConnStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "chain use: %v\n", err)
		return 1
	}
	chain, _, ok := resolveChain(store, ref)
	if !ok {
		fmt.Fprintf(os.Stderr, "chain use: chain %q not found\n", ref)
		return 1
	}
	store.ActiveChain = chain.Label
	if err := saveConnStore(store); err != nil {
		fmt.Fprintf(os.Stderr, "chain use: %v\n", err)
		return 1
	}
	if *jsonOut {
		return printJSON(chain)
	}
	fmt.Printf("active-chain: #%d %s\n", chain.Number, chain.Label)
	fmt.Printf("nodes: %s\n", formatChainNodes(chain.Nodes))
	return 0
}

func cmdChainCurrent(args []string) int {
	return cmdChainShow(args)
}

func cmdChainRemove(args []string) int {
	fs := flag.NewFlagSet("chain remove", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit removed chain as JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv chain remove LABEL|NUMBER [--json]")
		fs.PrintDefaults()
	}
	leading, rest := splitLeadingName(args)
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	ref := leading
	if ref == "" && fs.NArg() == 1 {
		ref = fs.Arg(0)
	} else if fs.NArg() != 0 || strings.TrimSpace(ref) == "" {
		fs.Usage()
		return 2
	}
	store, err := loadConnStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "chain remove: %v\n", err)
		return 1
	}
	chain, index, ok := resolveChain(store, ref)
	if !ok {
		fmt.Fprintf(os.Stderr, "chain remove: chain %q not found\n", ref)
		return 1
	}
	store.Chains = append(store.Chains[:index], store.Chains[index+1:]...)
	if store.ActiveChain == chain.Label {
		store.ActiveChain = ""
	}
	if err := saveConnStore(store); err != nil {
		fmt.Fprintf(os.Stderr, "chain remove: %v\n", err)
		return 1
	}
	if *jsonOut {
		return printJSON(chain)
	}
	fmt.Printf("chain removed: #%d %s\n", chain.Number, chain.Label)
	return 0
}

func cmdChainRename(args []string) int {
	jsonOut := false
	operands := make([]string, 0, 2)
	for _, arg := range args {
		switch arg {
		case "--json":
			jsonOut = true
		case "-h", "--help":
			fmt.Fprintln(os.Stderr, "usage: wv chain rename OLD NEW [--json]")
			return 0
		default:
			if strings.HasPrefix(arg, "-") {
				fmt.Fprintf(os.Stderr, "chain rename: unknown option %q\n", arg)
				return 2
			}
			operands = append(operands, arg)
		}
	}
	if len(operands) != 2 {
		fmt.Fprintln(os.Stderr, "usage: wv chain rename OLD NEW [--json]")
		return 2
	}
	oldRef := operands[0]
	newLabel := strings.TrimSpace(normalizeChainRef(operands[1]))
	if newLabel == "" || strings.HasPrefix(newLabel, "#") {
		fmt.Fprintln(os.Stderr, "chain rename: NEW must be a nonempty label")
		return 2
	}
	store, err := loadConnStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "chain rename: %v\n", err)
		return 1
	}
	chain, index, ok := resolveChain(store, oldRef)
	if !ok {
		fmt.Fprintf(os.Stderr, "chain rename: chain %q not found\n", oldRef)
		return 1
	}
	if existing, _, exists := findChain(store, newLabel); exists && existing.Label != chain.Label {
		fmt.Fprintf(os.Stderr, "chain rename: chain %q already exists\n", newLabel)
		return 1
	}
	oldLabel := chain.Label
	chain.Label = newLabel
	store.Chains[index] = chain
	if store.ActiveChain == oldLabel {
		store.ActiveChain = newLabel
	}
	if err := saveConnStore(store); err != nil {
		fmt.Fprintf(os.Stderr, "chain rename: %v\n", err)
		return 1
	}
	if jsonOut {
		return printJSON(chain)
	}
	fmt.Printf("chain renamed: %s -> %s (#%d)\n", oldLabel, newLabel, chain.Number)
	return 0
}

func cmdChainClear(args []string) int {
	fs := flag.NewFlagSet("chain clear", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv chain clear [--json]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	store, err := loadConnStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "chain clear: %v\n", err)
		return 1
	}
	previous := store.ActiveChain
	store.ActiveChain = ""
	if err := saveConnStore(store); err != nil {
		fmt.Fprintf(os.Stderr, "chain clear: %v\n", err)
		return 1
	}
	if *jsonOut {
		return printJSON(map[string]any{"active": "", "previous": previous})
	}
	fmt.Println("active-chain: none")
	return 0
}

func printChain(chain ConnChain, active bool) {
	fmt.Printf("chain: #%d %s\n", chain.Number, chain.Label)
	fmt.Printf("active: %t\n", active)
	fmt.Printf("nodes: %s\n", formatChainNodes(chain.Nodes))
	if chain.Description != "" {
		fmt.Printf("description: %s\n", chain.Description)
	}
	if len(chain.Tags) > 0 {
		tags := append([]string(nil), chain.Tags...)
		sort.Strings(tags)
		fmt.Printf("tags: %s\n", strings.Join(tags, ","))
	}
	if len(chain.Labels) > 0 {
		fmt.Printf("labels: %s\n", formatLabels(chain.Labels))
	}
}

func printChainHelp() {
	fmt.Print(`wv chain - manage ordered SSH/weaverssh node chains

Usage:
  wv chain list [--json]
  wv chain set LABEL --nodes local,jump,endpoint [--number N] [--append]
  wv chain show [LABEL|NUMBER] [--json]
  wv chain use LABEL|NUMBER [--json]
  wv chain current [--json]
  wv chain rename OLD NEW [--json]
  wv chain remove LABEL|NUMBER [--json]
  wv chain clear [--json]

Aliases:
  wv connections chain <command> ...
  chain create/update/configure -> chain set
  chain select -> chain use
  chain delete/rm -> chain remove

References:
  LABEL, NUMBER, #NUMBER, chain/LABEL, and chains/LABEL are accepted.
`)
}

func init() {
	for _, command := range []string{"chain", "chains", "rmdir", "stat"} {
		found := false
		for _, existing := range topLevelCommands {
			if existing == command {
				found = true
				break
			}
		}
		if !found {
			topLevelCommands = append(topLevelCommands, command)
		}
	}
	sort.Strings(topLevelCommands)
}
