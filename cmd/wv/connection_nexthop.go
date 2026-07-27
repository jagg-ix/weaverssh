package main

// Tier-1.5 dynamic path construction: resolve a hop at the node that makes it.
//
// A node running mid-chain uses `wv connections next-hop` to compute its own
// outgoing target: it finds itself in the path and resolves the following step.
// If that step is a "group:NAME" selector, a lookup/alias picks one member —
// constrained to the node's OWN signed node-context (its authorized topology),
// so no new trust is introduced. The concrete target then feeds session-host:
//
//	target=$(wv connections next-hop mychain --node-context node1.ctx --ssh \
//	           --resolver computes=exec:./pick-compute)
//	wv session-host --node-context node1.ctx --public-key-file key.pub \
//	  -- ssh -X "$target"

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

func cmdConnectionsNextHop(args []string) int {
	// Optional leading CHAIN positional, before flags.
	chainRef := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		chainRef = args[0]
		args = args[1:]
	}
	fs := flag.NewFlagSet("connections next-hop", flag.ContinueOnError)
	self := fs.String("self", "", "this node's id (default: current_node from --node-context)")
	nodeContext := fs.String("node-context", "", "signed node-context JSON; supplies self and the pre-authorized set")
	signedNodes := fs.String("signed-nodes", "", "additional comma-separated pre-authorized node set")
	var selects kvFlag
	var resolvers kvFlag
	fs.Var(&selects, "select", "pin a group to a member: GROUP=MEMBER (repeatable)")
	fs.Var(&resolvers, "resolver", "resolve a group via a program: GROUP=exec:CMD (repeatable)")
	sshOut := fs.Bool("ssh", false, "print the resolved node's ssh destination ([user@]host) from its profile")
	jsonOut := fs.Bool("json", false, "emit the resolution as JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv connections next-hop [CHAIN] [--self NODE | --node-context F] [--select G=M] [--resolver G=exec:CMD] [--ssh]")
		fmt.Fprintln(os.Stderr, "  Resolve this node's outgoing target: the chain step after --self, with a")
		fmt.Fprintln(os.Stderr, "  group:NAME selector resolved to one member of the node's signed set.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	ctxSelf, ctxNodes, err := readNodeContext(*nodeContext)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connections next-hop: %v\n", err)
		return 1
	}
	me := strings.TrimSpace(*self)
	if me == "" {
		me = ctxSelf
	}
	if me == "" {
		fmt.Fprintln(os.Stderr, "connections next-hop: need --self NODE or --node-context with a current_node")
		return 2
	}
	signed, err := loadSignedNodeSet(*signedNodes, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "connections next-hop: %v\n", err)
		return 1
	}
	if len(ctxNodes) > 0 {
		if signed == nil {
			signed = map[string]bool{}
		}
		for _, n := range ctxNodes {
			signed[strings.TrimSpace(n)] = true
		}
	}

	store, err := loadConnStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "connections next-hop: %v\n", err)
		return 1
	}
	chain, _, ok := resolveChain(store, chainRef)
	if !ok {
		fmt.Fprintln(os.Stderr, "connections next-hop: no chain (give a chain name or set an active chain)")
		return 1
	}
	idx := chainIndexOf(chain.Nodes, me)
	if idx < 0 {
		fmt.Fprintf(os.Stderr, "connections next-hop: node %q is not in chain %q\n", me, chain.Label)
		return 1
	}
	if idx == len(chain.Nodes)-1 {
		// Endpoint: no outgoing hop.
		if *jsonOut {
			return printJSON(map[string]any{"chain": chain.Label, "self": me, "endpoint": true})
		}
		fmt.Fprintln(os.Stderr, "connections next-hop: this node is the chain endpoint (no next hop)")
		return 0
	}

	nextStep := chain.Nodes[idx+1]
	target, err := resolveStep(store, nextStep, selects, resolvers, signed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connections next-hop: %v\n", err)
		return 1
	}

	if *sshOut {
		profile, _, found := findProfile(store, target)
		if !found {
			fmt.Fprintf(os.Stderr, "connections next-hop: no profile for resolved node %q (needed for --ssh)\n", target)
			return 1
		}
		dest, err := sshDestination(profile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "connections next-hop: %v\n", err)
			return 1
		}
		if *jsonOut {
			return printJSON(map[string]any{"chain": chain.Label, "self": me, "next_node": target, "ssh": dest})
		}
		fmt.Println(dest)
		return 0
	}

	if *jsonOut {
		return printJSON(map[string]any{"chain": chain.Label, "self": me, "next_node": target, "next_step": nextStep})
	}
	fmt.Println(target)
	return 0
}

// readNodeContext reads current_node and the signed node set from a node-context
// JSON. It accepts both the signed envelope ({"context":{...},"signature":...},
// as written by `wv node-context sign-services`) and a flat {current_node,nodes}
// object. An empty path yields empty values (no error).
func readNodeContext(path string) (current string, nodes []string, err error) {
	if strings.TrimSpace(path) == "" {
		return "", nil, nil
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		return "", nil, fmt.Errorf("node-context: %w", readErr)
	}
	var env struct {
		Context *struct {
			CurrentNode string   `json:"current_node"`
			Nodes       []string `json:"nodes"`
		} `json:"context"`
		CurrentNode string   `json:"current_node"`
		Nodes       []string `json:"nodes"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		return "", nil, fmt.Errorf("node-context: %w", err)
	}
	if env.Context != nil {
		return strings.TrimSpace(env.Context.CurrentNode), env.Context.Nodes, nil
	}
	return strings.TrimSpace(env.CurrentNode), env.Nodes, nil
}

// chainIndexOf returns the index of a concrete node self in the chain, or -1.
func chainIndexOf(nodes []string, self string) int {
	self = strings.ToLower(strings.TrimSpace(self))
	for i, n := range nodes {
		if _, isSelector := selectorGroup(n); isSelector {
			continue
		}
		if strings.ToLower(strings.TrimSpace(normalizeNodeRef(n))) == self {
			return i
		}
	}
	return -1
}

// sshDestination renders a profile as an ssh destination [user@]host.
func sshDestination(p ConnProfile) (string, error) {
	host := strings.TrimSpace(p.SSHHost)
	if host == "" {
		return "", fmt.Errorf("profile %q has no ssh_host", p.Name)
	}
	if user := strings.TrimSpace(p.SSHUser); user != "" {
		return user + "@" + host, nil
	}
	return host, nil
}
