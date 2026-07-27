package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

// cmdConnectionsComplete adds the missing local profile lifecycle operations and
// delegates all established profile and chain commands to their existing
// dispatchers.
func cmdConnectionsComplete(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "remove", "delete", "rm":
			return cmdConnectionRemove(args[1:])
		case "rename", "mv":
			return cmdConnectionRename(args[1:])
		case "clear":
			return cmdConnectionClear(args[1:])
		case "group", "groups":
			return cmdConnectionsGroup(args[1:])
		case "resolve":
			return cmdConnectionsResolve(args[1:])
		case "next-hop", "nexthop":
			return cmdConnectionsNextHop(args[1:])
		case "help", "-h", "--help":
			printConnectionsHelp()
			fmt.Fprintln(os.Stderr, `
Additional profile lifecycle commands:
  remove NAME [--json]                 delete a stored profile
  rename OLD NEW [--json]              rename a profile and preserve active selection
  clear [--json]                       clear the active profile

Pre-authorized sets and dynamic paths:
  group set NAME --members a,b,c       define a pre-authorized candidate set
  group <list|show|remove> ...         manage groups
  resolve [CHAIN] [--select G=M] [--resolver G=exec:CMD] [--node-context F]
                                       expand group:NAME steps to a concrete path
  next-hop [CHAIN] --node-context F [--resolver G=exec:CMD] [--ssh]
                                       resolve this node's outgoing target (at the node)

Stored chain namespace:
  chain <list|set|show|use|current|rename|remove|clear> ...`)
			return 0
		}
	}
	return cmdConnectionsDispatch(args)
}

func cmdConnectionRemove(args []string) int {
	name, jsonOut, ok := parseNamedJSONCommand("connections remove", args)
	if !ok {
		fmt.Fprintln(os.Stderr, "usage: wv connections remove NAME [--json]")
		return 2
	}
	store, err := loadConnStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "connections remove: %v\n", err)
		return 1
	}
	profile, index, found := findProfile(store, name)
	if !found {
		fmt.Fprintf(os.Stderr, "connections remove: profile %q not found\n", name)
		return 1
	}
	store.Profiles = append(store.Profiles[:index], store.Profiles[index+1:]...)
	if store.Active == profile.Name {
		store.Active = ""
	}
	if err := saveConnStore(store); err != nil {
		fmt.Fprintf(os.Stderr, "connections remove: %v\n", err)
		return 1
	}
	if jsonOut {
		return printJSON(profile)
	}
	fmt.Printf("profile removed: %s\n", profile.Name)
	return 0
}

func cmdConnectionRename(args []string) int {
	jsonOut := false
	operands := make([]string, 0, 2)
	for _, arg := range args {
		switch arg {
		case "--json":
			jsonOut = true
		case "-h", "--help":
			fmt.Fprintln(os.Stderr, "usage: wv connections rename OLD NEW [--json]")
			return 0
		default:
			if strings.HasPrefix(arg, "-") {
				fmt.Fprintf(os.Stderr, "connections rename: unknown option %q\n", arg)
				return 2
			}
			operands = append(operands, arg)
		}
	}
	if len(operands) != 2 {
		fmt.Fprintln(os.Stderr, "usage: wv connections rename OLD NEW [--json]")
		return 2
	}
	oldName := strings.TrimSpace(operands[0])
	newName := strings.TrimSpace(operands[1])
	if oldName == "" || newName == "" {
		fmt.Fprintln(os.Stderr, "connections rename: OLD and NEW must be nonempty")
		return 2
	}
	store, err := loadConnStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "connections rename: %v\n", err)
		return 1
	}
	profile, index, found := findProfile(store, oldName)
	if !found {
		fmt.Fprintf(os.Stderr, "connections rename: profile %q not found\n", oldName)
		return 1
	}
	if existing, _, exists := findProfile(store, newName); exists && existing.Name != profile.Name {
		fmt.Fprintf(os.Stderr, "connections rename: profile %q already exists\n", newName)
		return 1
	}
	profile.Name = newName
	store.Profiles[index] = profile
	if store.Active == oldName {
		store.Active = newName
	}
	if err := saveConnStore(store); err != nil {
		fmt.Fprintf(os.Stderr, "connections rename: %v\n", err)
		return 1
	}
	if jsonOut {
		return printJSON(profile)
	}
	fmt.Printf("profile renamed: %s -> %s\n", oldName, newName)
	return 0
}

func cmdConnectionClear(args []string) int {
	fs := flag.NewFlagSet("connections clear", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv connections clear [--json]")
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
		fmt.Fprintf(os.Stderr, "connections clear: %v\n", err)
		return 1
	}
	previous := store.Active
	store.Active = ""
	if err := saveConnStore(store); err != nil {
		fmt.Fprintf(os.Stderr, "connections clear: %v\n", err)
		return 1
	}
	if *jsonOut {
		return printJSON(map[string]any{"active": "", "previous": previous})
	}
	fmt.Println("active profile: none")
	return 0
}

func parseNamedJSONCommand(command string, args []string) (string, bool, bool) {
	name := ""
	jsonOut := false
	for _, arg := range args {
		switch arg {
		case "--json":
			jsonOut = true
		case "-h", "--help":
			return "", false, false
		default:
			if strings.HasPrefix(arg, "-") || name != "" {
				return "", false, false
			}
			name = strings.TrimSpace(arg)
		}
	}
	return name, jsonOut, name != ""
}
