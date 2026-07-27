package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// ConnChain records an ordered SSH jump path by reusable node/profile names.
// The first node is normally local/origin, intermediate nodes are jumps, and
// the last node is the endpoint. The numeric ID gives operators a compact,
// stable shorthand for dashboards, logs, and runbooks.
type ConnChain struct {
	Number      int               `json:"number"`
	Label       string            `json:"label"`
	Description string            `json:"description,omitempty"`
	Nodes       []string          `json:"nodes"`
	Tags        []string          `json:"tags,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

func connectionsArgsDefineNodes(args []string) bool {
	for _, arg := range args {
		switch {
		case arg == "--node" || arg == "-node" || arg == "--nodes" || arg == "-nodes":
			return true
		case strings.HasPrefix(arg, "--node=") || strings.HasPrefix(arg, "-node="):
			return true
		case strings.HasPrefix(arg, "--nodes=") || strings.HasPrefix(arg, "-nodes="):
			return true
		}
	}
	return false
}

func cmdConnectionsNodes(args []string) int {
	fs := flag.NewFlagSet("connections", flag.ContinueOnError)
	label := fs.String("label", "", "human chain label (default: chain-N)")
	labelAlias := fs.String("name", "", "alias for --label")
	number := fs.Int("number", 0, "positive chain number (default: next available)")
	numberAlias := fs.Int("n", 0, "short alias for --number")
	description := fs.String("description", "", "human description")
	appendMode := fs.Bool("append", false, "append nodes to an existing/active chain instead of replacing")
	active := fs.Bool("active", true, "mark the resulting chain active")
	jsonOut := fs.Bool("json", false, "emit saved chain as JSON")
	var nodes nodeList
	var tags tagList
	var labels labelAssignments
	fs.Var(&nodes, "node", "ordered node/profile list; repeatable; accepts comma, arrow, node/name, or profile/name syntax")
	fs.Var(&nodes, "nodes", "alias for --node")
	fs.Var(&tags, "tag", "chain tag (repeatable)")
	fs.Var(&labels, "set-label", "Kubernetes-style label KEY=VALUE; repeatable")
	fs.Var(&labels, "labels", "comma-separated Kubernetes-style labels KEY=VALUE[,KEY=VALUE]")
	fs.Var(&labels, "l", "short alias for --set-label")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv connections --node node/node1,node/node2[,node/node3] [--name NAME] [--number N]")
		fmt.Fprintln(os.Stderr, "       wv connections --nodes 'local->node/linode-a->node/linode-b' --name linodes --number 1 -l env=prod")
		fmt.Fprintln(os.Stderr, "       wv connections --name linodes --append --node node/next-hop")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	nodes = normalizeNodeList(nodes)
	if len(nodes) == 0 {
		fmt.Fprintln(os.Stderr, "connections: --node/--nodes requires at least one node")
		return 2
	}

	store, err := loadConnStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "connections: %v\n", err)
		return 1
	}

	if *label == "" && *labelAlias != "" {
		*label = *labelAlias
	}
	if *number == 0 && *numberAlias > 0 {
		*number = *numberAlias
	}
	if *appendMode && strings.TrimSpace(*label) == "" && store.ActiveChain != "" {
		*label = store.ActiveChain
	}
	if strings.TrimSpace(*label) != "" {
		if existing, _, ok := findChain(store, *label); ok && *number <= 0 {
			*number = existing.Number
		}
	}
	if *number <= 0 {
		*number = nextChainNumber(store)
	}
	if strings.TrimSpace(*label) == "" {
		*label = uniqueChainLabel(store, *number)
	}
	if *number <= 0 {
		fmt.Fprintln(os.Stderr, "connections: --number must be positive")
		return 2
	}

	chain, _, found := findChain(store, *label)
	if found && chain.Number != *number {
		if existing, _, ok := findChainByNumber(store, *number); ok && existing.Label != chain.Label {
			fmt.Fprintf(os.Stderr, "connections: number %d already belongs to %q\n", *number, existing.Label)
			return 1
		}
		chain.Number = *number
	} else if !found {
		if existing, _, ok := findChainByNumber(store, *number); ok && existing.Label != *label {
			fmt.Fprintf(os.Stderr, "connections: number %d already belongs to %q\n", *number, existing.Label)
			return 1
		}
		chain = ConnChain{Number: *number, Label: strings.TrimSpace(*label)}
	}
	if *appendMode {
		chain.Nodes = append(chain.Nodes, nodes...)
	} else {
		chain.Nodes = nodes
	}
	chain.Nodes = normalizeNodeList(chain.Nodes)
	if err := validateChainNodes(chain.Nodes); err != nil {
		fmt.Fprintf(os.Stderr, "connections: %v\n", err)
		return 2
	}
	if strings.TrimSpace(*description) != "" || !found {
		chain.Description = strings.TrimSpace(*description)
	}
	if len(tags) > 0 || !found {
		chain.Tags = tags
	}
	if len(labels) > 0 {
		chain.Labels = mergeLabels(chain.Labels, labels)
	}
	store = upsertChain(store, chain)
	if *active {
		store.ActiveChain = chain.Label
	}
	if err := saveConnStore(store); err != nil {
		fmt.Fprintf(os.Stderr, "connections: %v\n", err)
		return 1
	}
	if *jsonOut {
		return printJSON(chain)
	}
	fmt.Printf("chain saved: #%d %s\n", chain.Number, chain.Label)
	fmt.Printf("nodes: %s\n", formatChainNodes(chain.Nodes))
	fmt.Printf("store: %s\n", connectionsStorePath())
	if *active {
		fmt.Printf("active-chain: %s\n", chain.Label)
	}
	return 0
}

type nodeList []string

func (n *nodeList) String() string { return strings.Join(*n, ",") }

func (n *nodeList) Set(v string) error {
	*n = append(*n, splitChainNodes(v)...)
	return nil
}

func splitChainNodes(raw string) []string {
	repl := strings.NewReplacer("->", ",", "=>", ",", "→", ",")
	raw = repl.Replace(raw)
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '+' || r == ';' || unicode.IsSpace(r)
	})
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		field = strings.Trim(field, "[]()")
		if field != "" {
			out = append(out, field)
		}
	}
	return out
}

func normalizeNodeList(nodes []string) []string {
	out := make([]string, 0, len(nodes))
	for _, node := range nodes {
		node = normalizeNodeRef(node)
		if node != "" {
			out = append(out, node)
		}
	}
	return out
}

func validateChainNodes(nodes []string) error {
	seen := map[string]bool{}
	for _, node := range nodes {
		if strings.TrimSpace(node) == "" {
			return fmt.Errorf("node name cannot be empty")
		}
		key := strings.ToLower(node)
		if seen[key] {
			return fmt.Errorf("node %q appears more than once", node)
		}
		seen[key] = true
	}
	return nil
}

func sortChains(chains []ConnChain) {
	sort.Slice(chains, func(i, j int) bool {
		if chains[i].Number == chains[j].Number {
			return chains[i].Label < chains[j].Label
		}
		return chains[i].Number < chains[j].Number
	})
}

func findChain(store ConnStore, label string) (ConnChain, int, bool) {
	for i, chain := range store.Chains {
		if chain.Label == label {
			return chain, i, true
		}
	}
	return ConnChain{}, -1, false
}

func findChainByNumber(store ConnStore, number int) (ConnChain, int, bool) {
	for i, chain := range store.Chains {
		if chain.Number == number {
			return chain, i, true
		}
	}
	return ConnChain{}, -1, false
}

func resolveChain(store ConnStore, ref string) (ConnChain, int, bool) {
	ref = normalizeChainRef(ref)
	if ref == "" {
		if store.ActiveChain == "" {
			return ConnChain{}, -1, false
		}
		return findChain(store, store.ActiveChain)
	}
	if strings.HasPrefix(ref, "#") {
		if n, err := strconv.Atoi(strings.TrimPrefix(ref, "#")); err == nil {
			return findChainByNumber(store, n)
		}
	}
	if n, err := strconv.Atoi(ref); err == nil {
		if chain, i, ok := findChainByNumber(store, n); ok {
			return chain, i, true
		}
	}
	return findChain(store, ref)
}

func nextChainNumber(store ConnStore) int {
	max := 0
	for _, chain := range store.Chains {
		if chain.Number > max {
			max = chain.Number
		}
	}
	return max + 1
}

func uniqueChainLabel(store ConnStore, number int) string {
	if number <= 0 {
		number = nextChainNumber(store)
	}
	base := fmt.Sprintf("chain-%d", number)
	if _, _, ok := findChain(store, base); !ok {
		return base
	}
	for i := 2; ; i++ {
		candidate := fmt.Sprintf("%s-%d", base, i)
		if _, _, ok := findChain(store, candidate); !ok {
			return candidate
		}
	}
}

func upsertChain(store ConnStore, chain ConnChain) ConnStore {
	if _, i, ok := findChain(store, chain.Label); ok {
		store.Chains[i] = chain
		return store
	}
	store.Chains = append(store.Chains, chain)
	return store
}

func normalizeNodeRef(ref string) string {
	ref = strings.TrimSpace(ref)
	lower := strings.ToLower(ref)
	// A selector step chooses one member of a pre-authorized group at resolve
	// time. Accept "group:NAME", "groups/NAME", and the shorthand "@NAME",
	// canonicalizing to "group:NAME".
	if strings.HasPrefix(ref, "@") && len(ref) > 1 {
		return "group:" + strings.TrimSpace(ref[1:])
	}
	if strings.HasPrefix(lower, "group:") {
		return "group:" + strings.TrimSpace(ref[len("group:"):])
	}
	if strings.HasPrefix(lower, "groups/") {
		return "group:" + strings.TrimSpace(ref[len("groups/"):])
	}
	for _, prefix := range []string{"node/", "nodes/", "profile/", "profiles/", "connection/", "connections/"} {
		if strings.HasPrefix(lower, prefix) {
			return strings.TrimSpace(ref[len(prefix):])
		}
	}
	return ref
}

// selectorGroup reports whether ref is a group selector step and returns the
// group name.
func selectorGroup(ref string) (string, bool) {
	ref = strings.TrimSpace(ref)
	if strings.HasPrefix(strings.ToLower(ref), "group:") {
		return strings.TrimSpace(ref[len("group:"):]), true
	}
	return "", false
}

func normalizeChainRef(ref string) string {
	ref = strings.TrimSpace(ref)
	lower := strings.ToLower(ref)
	for _, prefix := range []string{"chain/", "chains/"} {
		if strings.HasPrefix(lower, prefix) {
			return strings.TrimSpace(ref[len(prefix):])
		}
	}
	return ref
}

type labelAssignments map[string]string

func (l *labelAssignments) String() string {
	return formatLabels(*l)
}

func (l *labelAssignments) Set(v string) error {
	if *l == nil {
		*l = map[string]string{}
	}
	for _, part := range splitLabelCSV(v) {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			return fmt.Errorf("label %q must be KEY=VALUE", part)
		}
		key = strings.TrimSpace(key)
		if key == "" {
			return fmt.Errorf("label key cannot be empty")
		}
		(*l)[key] = strings.TrimSpace(value)
	}
	return nil
}

func mergeLabels(base map[string]string, updates map[string]string) map[string]string {
	if len(base) == 0 && len(updates) == 0 {
		return nil
	}
	out := map[string]string{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range updates {
		out[k] = v
	}
	return out
}

func formatLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+labels[k])
	}
	return strings.Join(parts, ",")
}

func splitLabelCSV(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func formatChainNodes(nodes []string) string {
	if len(nodes) == 0 {
		return "-"
	}
	return strings.Join(nodes, " -> ")
}
