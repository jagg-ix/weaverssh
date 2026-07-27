package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"weaverssh/socksproof"
)

func cmdSocksPolicyRuntimeComplete(args []string) int {
	if len(args) > 0 && (args[0] == "capability" || args[0] == "capabilities") {
		return cmdSocksPolicyCapability(args[1:])
	}
	return cmdSocksPolicyComplete(args)
}

func cmdSocksPolicyCapability(args []string) int {
	if len(args) == 0 { printSocksCapabilityUsage(); return 2 }
	switch args[0] {
	case "list", "show": return cmdSocksCapabilityList(args[1:])
	case "add", "grant": return cmdSocksCapabilityMutate(args[1:], true)
	case "remove", "revoke": return cmdSocksCapabilityMutate(args[1:], false)
	case "help", "-h", "--help": printSocksCapabilityUsage(); return 0
	default: fmt.Fprintf(os.Stderr, "socks-policy capability: unknown command %q\n", args[0]); return 2
	}
}

func cmdSocksCapabilityList(args []string) int {
	leading, parseArgs := splitLeadingOperands(args, 2)
	fs := flag.NewFlagSet("socks-policy capability list", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(parseArgs); err != nil { return 2 }
	operands := append(leading, fs.Args()...)
	if len(operands) != 2 { printSocksCapabilityUsage(); return 2 }
	policy, err := socksproof.LoadPolicyFile(operands[0]); if err != nil { fmt.Fprintf(os.Stderr, "socks-policy capability list: %v\n", err); return 1 }
	principal, ok := findSocksPrincipal(policy, operands[1]); if !ok { fmt.Fprintf(os.Stderr, "socks-policy capability list: principal %q not found\n", operands[1]); return 1 }
	capabilities := append([]string(nil), principal.Capabilities...); sort.Strings(capabilities)
	if *jsonOut { return printJSON(map[string]any{"principal": principal.ID, "capabilities": capabilities}) }
	for _, capability := range capabilities { fmt.Println(capability) }
	return 0
}

func cmdSocksCapabilityMutate(args []string, add bool) int {
	leading, parseArgs := splitLeadingOperands(args, 3)
	fs := flag.NewFlagSet("socks-policy capability", flag.ContinueOnError)
	out := fs.String("out", "", "write updated policy to file")
	inPlace := fs.Bool("in-place", false, "atomically replace input policy")
	force := fs.Bool("force", false, "replace existing output")
	if err := fs.Parse(parseArgs); err != nil { return 2 }
	operands := append(leading, fs.Args()...)
	if len(operands) != 3 || (*inPlace && strings.TrimSpace(*out) != "") { printSocksCapabilityUsage(); return 2 }
	input, principalID, capability := operands[0], strings.TrimSpace(operands[1]), strings.TrimSpace(operands[2])
	if !knownSocksPolicyCapability(capability) { fmt.Fprintf(os.Stderr, "socks-policy capability: unsupported capability %q\n", capability); return 2 }
	if !add && capability == socksproof.CapabilityConnect { fmt.Fprintln(os.Stderr, "socks-policy capability: socks.connect cannot be removed"); return 2 }
	policy, err := socksproof.LoadPolicyFile(input); if err != nil { fmt.Fprintf(os.Stderr, "socks-policy capability: %v\n", err); return 1 }
	found := false
	for index := range policy.Principals {
		if policy.Principals[index].ID != principalID { continue }
		found = true
		values := append([]string(nil), policy.Principals[index].Capabilities...)
		if add { values = append(values, capability) } else { filtered := values[:0]; for _, value := range values { if value != capability { filtered = append(filtered, value) } }; values = filtered }
		policy.Principals[index].Capabilities = normalizedUniqueStrings(values)
		break
	}
	if !found { fmt.Fprintf(os.Stderr, "socks-policy capability: principal %q not found\n", principalID); return 1 }
	policy, err = socksproof.NormalizePolicy(policy); if err != nil { fmt.Fprintf(os.Stderr, "socks-policy capability: %v\n", err); return 1 }
	destination := strings.TrimSpace(*out); replace := *force
	if *inPlace { destination = input; replace = true }
	return emitOrWriteSocksPolicy("socks-policy capability", destination, policy, replace)
}

func knownSocksPolicyCapability(value string) bool {
	switch value { case socksproof.CapabilityConnect, socksproof.CapabilityBind, socksproof.CapabilityUDPAssociate: return true; default: return false }
}

func printSocksCapabilityUsage() {
	fmt.Print(`usage: wv socks-policy capability <command> [options]

Commands:
  list POLICY.json PRINCIPAL [--json]
  add POLICY.json PRINCIPAL socks.bind|socks.udp-associate [--in-place|--out FILE]
  remove POLICY.json PRINCIPAL socks.bind|socks.udp-associate [--in-place|--out FILE]
`)
}
