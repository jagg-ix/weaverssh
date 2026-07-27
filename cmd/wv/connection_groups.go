package main

// Tier-1 dynamic path construction: a connection path (chain) may contain a
// selector step "group:NAME" that is resolved to one member of a pre-authorized
// group at path-construction time. Because every candidate is declared up front
// (and can be checked against a signed node-context), the resolved hop never
// leaves the authorized set — the origin still knows the full topology, it just
// lets a lookup/alias pick which authorized node to use.

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
)

// ConnGroup is a named, pre-authorized candidate set for a selector step.
type ConnGroup struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Members     []string `json:"members"`
}

func findGroup(store ConnStore, name string) (ConnGroup, int, bool) {
	name = strings.TrimSpace(name)
	for i, g := range store.Groups {
		if strings.EqualFold(g.Name, name) {
			return g, i, true
		}
	}
	return ConnGroup{}, -1, false
}

func upsertGroup(store ConnStore, group ConnGroup) ConnStore {
	if _, i, ok := findGroup(store, group.Name); ok {
		store.Groups[i] = group
		return store
	}
	store.Groups = append(store.Groups, group)
	return store
}

func groupContains(group ConnGroup, member string) bool {
	member = strings.TrimSpace(member)
	for _, m := range group.Members {
		if strings.EqualFold(strings.TrimSpace(m), member) {
			return true
		}
	}
	return false
}

// kvFlag is a repeatable KEY=VALUE flag; the value may contain '=' and commas.
type kvFlag map[string]string

func (k *kvFlag) String() string { return "" }
func (k *kvFlag) Set(v string) error {
	i := strings.IndexByte(v, '=')
	if i <= 0 {
		return fmt.Errorf("expected KEY=VALUE, got %q", v)
	}
	if *k == nil {
		*k = kvFlag{}
	}
	(*k)[strings.TrimSpace(v[:i])] = strings.TrimSpace(v[i+1:])
	return nil
}

// ---- wv connections group ----------------------------------------------------

func cmdConnectionsGroup(args []string) int {
	if len(args) == 0 {
		printGroupUsage()
		return 2
	}
	switch args[0] {
	case "set", "add", "configure":
		return groupSet(args[1:])
	case "list", "ls":
		return groupList(args[1:])
	case "show", "get":
		return groupShow(args[1:])
	case "remove", "rm", "delete":
		return groupRemove(args[1:])
	case "help", "-h", "--help":
		printGroupUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "connections group: unknown command %q\n", args[0])
		printGroupUsage()
		return 2
	}
}

func printGroupUsage() {
	fmt.Fprintln(os.Stderr, `usage: wv connections group <command>
  set NAME --members a,b,c [--description D]   define/replace a pre-authorized set
  list                                         list groups
  show NAME                                    show one group
  remove NAME                                  delete a group

A chain step "group:NAME" (or "@NAME") is resolved to one member of the group by
wv connections resolve.`)
}

func groupSet(args []string) int {
	// NAME is positional and leads the flags, so pull it before flag parsing
	// (Go's flag package stops at the first non-flag argument).
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		fmt.Fprintln(os.Stderr, "usage: wv connections group set NAME --members a,b,c [--description D]")
		return 2
	}
	name := strings.TrimSpace(args[0])
	fs := flag.NewFlagSet("connections group set", flag.ContinueOnError)
	var members nodeList
	fs.Var(&members, "members", "comma-separated members (repeatable)")
	fs.Var(&members, "member", "alias for --members")
	description := fs.String("description", "", "human description")
	jsonOut := fs.Bool("json", false, "emit JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv connections group set NAME --members a,b,c [--description D]")
	}
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if name == "" || len(members) == 0 {
		fs.Usage()
		return 2
	}
	group := ConnGroup{Name: name, Description: strings.TrimSpace(*description), Members: normalizeNodeList(members)}
	if len(group.Members) == 0 {
		fmt.Fprintln(os.Stderr, "connections group set: no usable members")
		return 2
	}
	store, err := loadConnStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "connections group set: %v\n", err)
		return 1
	}
	store = upsertGroup(store, group)
	if err := saveConnStore(store); err != nil {
		fmt.Fprintf(os.Stderr, "connections group set: %v\n", err)
		return 1
	}
	if *jsonOut {
		return printJSON(group)
	}
	fmt.Printf("group saved: %s  [%s]\n", group.Name, strings.Join(group.Members, ", "))
	return 0
}

func groupList(args []string) int {
	jsonOut := false
	for _, a := range args {
		if a == "--json" {
			jsonOut = true
		}
	}
	store, err := loadConnStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "connections group list: %v\n", err)
		return 1
	}
	groups := append([]ConnGroup(nil), store.Groups...)
	sort.Slice(groups, func(i, j int) bool { return groups[i].Name < groups[j].Name })
	if jsonOut {
		return printJSON(groups)
	}
	fmt.Printf("store: %s\n", connectionsStorePath())
	if len(groups) == 0 {
		fmt.Println("groups: none")
		return 0
	}
	fmt.Println("groups:")
	for _, g := range groups {
		fmt.Printf("  %s  [%s]\n", g.Name, strings.Join(g.Members, ", "))
	}
	return 0
}

func groupShow(args []string) int {
	name, jsonOut, ok := parseNamedJSONCommand("connections group show", args)
	if !ok {
		fmt.Fprintln(os.Stderr, "usage: wv connections group show NAME [--json]")
		return 2
	}
	store, err := loadConnStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "connections group show: %v\n", err)
		return 1
	}
	group, _, found := findGroup(store, name)
	if !found {
		fmt.Fprintf(os.Stderr, "connections group show: group %q not found\n", name)
		return 1
	}
	if jsonOut {
		return printJSON(group)
	}
	fmt.Printf("group:    %s\n", group.Name)
	if group.Description != "" {
		fmt.Printf("desc:     %s\n", group.Description)
	}
	fmt.Printf("members:  %s\n", strings.Join(group.Members, ", "))
	return 0
}

func groupRemove(args []string) int {
	name, jsonOut, ok := parseNamedJSONCommand("connections group remove", args)
	if !ok {
		fmt.Fprintln(os.Stderr, "usage: wv connections group remove NAME [--json]")
		return 2
	}
	store, err := loadConnStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "connections group remove: %v\n", err)
		return 1
	}
	group, index, found := findGroup(store, name)
	if !found {
		fmt.Fprintf(os.Stderr, "connections group remove: group %q not found\n", name)
		return 1
	}
	store.Groups = append(store.Groups[:index], store.Groups[index+1:]...)
	if err := saveConnStore(store); err != nil {
		fmt.Fprintf(os.Stderr, "connections group remove: %v\n", err)
		return 1
	}
	if jsonOut {
		return printJSON(group)
	}
	fmt.Printf("group removed: %s\n", group.Name)
	return 0
}

// ---- wv connections resolve --------------------------------------------------

func cmdConnectionsResolve(args []string) int {
	fs := flag.NewFlagSet("connections resolve", flag.ContinueOnError)
	var selects kvFlag
	var resolvers kvFlag
	fs.Var(&selects, "select", "pin a group to a member: GROUP=MEMBER (repeatable)")
	fs.Var(&resolvers, "resolver", "resolve a group via a program: GROUP=exec:CMD (repeatable)")
	signedNodes := fs.String("signed-nodes", "", "comma-separated pre-authorized node set to enforce")
	nodeContext := fs.String("node-context", "", "signed node-context JSON whose nodes are the pre-authorized set")
	save := fs.String("save", "", "save the resolved concrete path as a new chain with this label")
	jsonOut := fs.Bool("json", false, "emit the resolved path as JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv connections resolve [CHAIN] [--select G=M] [--resolver G=exec:CMD] [--signed-nodes L | --node-context F] [--save NAME]")
		fmt.Fprintln(os.Stderr, "  Expand a chain's group:NAME steps to concrete members. Each choice must be a")
		fmt.Fprintln(os.Stderr, "  group member, and (with --signed-nodes / --node-context) within the signed set.")
		fmt.Fprintln(os.Stderr, "  A resolver program receives WV_GROUP and WV_GROUP_MEMBERS and prints the member.")
		fs.PrintDefaults()
	}
	// CHAIN is an optional leading positional; pull it before flag parsing.
	chainRef := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		chainRef = args[0]
		args = args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	store, err := loadConnStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "connections resolve: %v\n", err)
		return 1
	}
	chain, _, ok := resolveChain(store, chainRef)
	if !ok {
		fmt.Fprintln(os.Stderr, "connections resolve: no chain (give a chain name or set an active chain)")
		return 1
	}
	signed, err := loadSignedNodeSet(*signedNodes, *nodeContext)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connections resolve: %v\n", err)
		return 1
	}
	resolved, err := resolvePath(store, chain, selects, resolvers, signed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connections resolve: %v\n", err)
		return 1
	}

	if *save != "" {
		saved := ConnChain{Number: nextChainNumber(store), Label: strings.TrimSpace(*save), Nodes: resolved, Description: "resolved from chain " + chain.Label}
		if err := validateChainNodes(saved.Nodes); err != nil {
			fmt.Fprintf(os.Stderr, "connections resolve: %v\n", err)
			return 1
		}
		store = upsertChain(store, saved)
		if err := saveConnStore(store); err != nil {
			fmt.Fprintf(os.Stderr, "connections resolve: %v\n", err)
			return 1
		}
	}

	if *jsonOut {
		return printJSON(map[string]any{"chain": chain.Label, "nodes": resolved})
	}
	fmt.Printf("resolved %s: %s\n", chain.Label, formatChainNodes(resolved))
	if *save != "" {
		fmt.Printf("saved as chain: %s\n", strings.TrimSpace(*save))
	}
	return 0
}

// resolvePath expands each group:NAME selector in chain.Nodes to a concrete
// member. selects pins a group to a member; resolvers run a program per group;
// a single-member group resolves to that member. Every choice must be a group
// member, and — when signed is non-nil — within the signed node set.
func resolvePath(store ConnStore, chain ConnChain, selects, resolvers map[string]string, signed map[string]bool) ([]string, error) {
	out := make([]string, 0, len(chain.Nodes))
	for _, node := range chain.Nodes {
		resolved, err := resolveStep(store, node, selects, resolvers, signed)
		if err != nil {
			return nil, err
		}
		out = append(out, resolved)
	}
	return out, nil
}

// resolveStep resolves a single chain step: a concrete node passes through; a
// "group:NAME" selector is resolved to one member, checked against the group and
// (when signed is non-nil) the signed node set.
func resolveStep(store ConnStore, node string, selects, resolvers map[string]string, signed map[string]bool) (string, error) {
	group, isSelector := selectorGroup(node)
	if !isSelector {
		return node, nil
	}
	g, _, ok := findGroup(store, group)
	if !ok {
		return "", fmt.Errorf("unknown group %q", group)
	}
	if len(g.Members) == 0 {
		return "", fmt.Errorf("group %q has no members", group)
	}
	if signed != nil {
		for _, m := range g.Members {
			if !signed[strings.TrimSpace(m)] {
				return "", fmt.Errorf("group %q member %q is not in the signed node set", group, m)
			}
		}
	}
	chosen, err := chooseGroupMember(g, selects[group], resolvers[group])
	if err != nil {
		return "", err
	}
	if !groupContains(g, chosen) {
		return "", fmt.Errorf("%q is not a member of group %q", chosen, group)
	}
	if signed != nil && !signed[chosen] {
		return "", fmt.Errorf("resolved target %q is not in the signed node set", chosen)
	}
	return chosen, nil
}

func chooseGroupMember(g ConnGroup, pin, resolver string) (string, error) {
	if pin = strings.TrimSpace(pin); pin != "" {
		return pin, nil
	}
	if resolver = strings.TrimSpace(resolver); resolver != "" {
		return runGroupResolver(g, resolver)
	}
	if len(g.Members) == 1 {
		return strings.TrimSpace(g.Members[0]), nil
	}
	return "", fmt.Errorf("group %q is ambiguous (%d members); pass --select %s=MEMBER or --resolver %s=exec:CMD", g.Name, len(g.Members), g.Name, g.Name)
}

// runGroupResolver runs an exec: resolver (or treats a bare value as a member).
// The program gets WV_GROUP and WV_GROUP_MEMBERS and prints the chosen member.
func runGroupResolver(g ConnGroup, resolver string) (string, error) {
	if !strings.HasPrefix(resolver, "exec:") {
		return resolver, nil
	}
	fields := strings.Fields(strings.TrimPrefix(resolver, "exec:"))
	if len(fields) == 0 {
		return "", errors.New("empty exec resolver")
	}
	cmd := exec.Command(fields[0], fields[1:]...)
	cmd.Env = append(os.Environ(), "WV_GROUP="+g.Name, "WV_GROUP_MEMBERS="+strings.Join(g.Members, ","))
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("resolver for group %q: %w", g.Name, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// loadSignedNodeSet builds the pre-authorized node set from an explicit list
// and/or a signed node-context JSON. Returns nil when neither is given (no
// signed-set constraint is enforced).
func loadSignedNodeSet(list, contextFile string) (map[string]bool, error) {
	set := map[string]bool{}
	for _, n := range splitChainNodes(list) {
		if n = strings.TrimSpace(n); n != "" {
			set[n] = true
		}
	}
	if strings.TrimSpace(contextFile) != "" {
		_, nodes, err := readNodeContext(contextFile)
		if err != nil {
			return nil, err
		}
		for _, n := range nodes {
			if n = strings.TrimSpace(n); n != "" {
				set[n] = true
			}
		}
	}
	if len(set) == 0 {
		return nil, nil
	}
	return set, nil
}
