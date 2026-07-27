package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"weaverssh/authproof"
	"weaverssh/socksproof"
)

func cmdSocksPolicyComplete(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "init", "create":
			return cmdSocksPolicyInit(args[1:])
		case "normalize", "format":
			return cmdSocksPolicyNormalize(args[1:])
		case "principal", "principals":
			return cmdSocksPolicyPrincipal(args[1:])
		case "help", "-h", "--help":
			printSocksPolicyUsage(os.Stdout)
			fmt.Fprint(os.Stdout, `
Configuration lifecycle:
  init --server-id ID --principal ID --public-key-file KEY --destination HOST:PORT [--out FILE]
  normalize POLICY.json [--out FILE|--in-place]
  principal list POLICY.json [--json]
  principal show POLICY.json ID [--json]
  principal add POLICY.json --id ID --public-key-file KEY --destination HOST:PORT [--out FILE|--in-place]
  principal remove POLICY.json ID [--out FILE|--in-place]
`)
			return 0
		}
	}
	return cmdSocksPolicy(args)
}

func cmdSocksPolicyInit(args []string) int {
	fs := flag.NewFlagSet("socks-policy init", flag.ContinueOnError)
	serverID := fs.String("server-id", "", "SOCKS proof server id")
	principalID := fs.String("principal", "", "initial principal id")
	publicKey := fs.String("public-key", "", "inline Ed25519 public key")
	publicKeyFile := fs.String("public-key-file", "", "Ed25519 public-key file")
	maxTTL := fs.String("max-ttl", "30s", "maximum principal proof TTL")
	out := fs.String("out", "", "write policy JSON to file")
	force := fs.Bool("force", false, "replace existing output")
	var destinations commaListFlag
	fs.Var(&destinations, "destination", "allowed HOST:PORT or glob; repeatable or comma-separated")
	fs.Var(&destinations, "destinations", "alias for --destination")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv socks-policy init --server-id ID --principal ID --public-key-file KEY --destination HOST:PORT [--out FILE]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || strings.TrimSpace(*serverID) == "" || strings.TrimSpace(*principalID) == "" || len(destinations) == 0 {
		fs.Usage()
		return 2
	}
	principal, err := buildSocksPolicyPrincipal(*principalID, *publicKey, *publicKeyFile, destinations, *maxTTL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "socks-policy init: %v\n", err)
		return 1
	}
	policy, err := socksproof.NormalizePolicy(socksproof.Policy{
		Version:    socksproof.PolicyVersion,
		ServerID:   *serverID,
		Principals: []socksproof.PrincipalPolicy{principal},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "socks-policy init: %v\n", err)
		return 1
	}
	return emitOrWriteSocksPolicy("socks-policy init", *out, policy, *force)
}

func cmdSocksPolicyNormalize(args []string) int {
	leading, parseArgs := splitLeadingOperands(args, 1)
	fs := flag.NewFlagSet("socks-policy normalize", flag.ContinueOnError)
	out := fs.String("out", "", "write normalized policy to file")
	inPlace := fs.Bool("in-place", false, "atomically replace the input policy")
	force := fs.Bool("force", false, "replace existing --out file")
	if err := fs.Parse(parseArgs); err != nil {
		return 2
	}
	operands := append(leading, fs.Args()...)
	if len(operands) != 1 || (*inPlace && strings.TrimSpace(*out) != "") {
		fmt.Fprintln(os.Stderr, "usage: wv socks-policy normalize POLICY.json [--out FILE|--in-place]")
		return 2
	}
	input := operands[0]
	policy, err := socksproof.LoadPolicyFile(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "socks-policy normalize: %v\n", err)
		return 1
	}
	destination := strings.TrimSpace(*out)
	replace := *force
	if *inPlace {
		destination = input
		replace = true
	}
	return emitOrWriteSocksPolicy("socks-policy normalize", destination, policy, replace)
}

func cmdSocksPolicyPrincipal(args []string) int {
	if len(args) == 0 {
		printSocksPrincipalUsage()
		return 2
	}
	switch args[0] {
	case "list", "ls":
		return cmdSocksPrincipalList(args[1:])
	case "show", "get":
		return cmdSocksPrincipalShow(args[1:])
	case "add", "set", "update":
		return cmdSocksPrincipalAdd(args[1:])
	case "remove", "delete", "rm":
		return cmdSocksPrincipalRemove(args[1:])
	case "help", "-h", "--help":
		printSocksPrincipalUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "socks-policy principal: unknown command %q\n", args[0])
		return 2
	}
}

func cmdSocksPrincipalList(args []string) int {
	leading, parseArgs := splitLeadingOperands(args, 1)
	fs := flag.NewFlagSet("socks-policy principal list", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(parseArgs); err != nil {
		return 2
	}
	operands := append(leading, fs.Args()...)
	if len(operands) != 1 {
		fmt.Fprintln(os.Stderr, "usage: wv socks-policy principal list POLICY.json [--json]")
		return 2
	}
	policy, err := socksproof.LoadPolicyFile(operands[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "socks-policy principal list: %v\n", err)
		return 1
	}
	if *jsonOut {
		return printJSON(policy.Principals)
	}
	for _, principal := range policy.Principals {
		key, _ := authproof.DecodePublicKey(principal.PublicKey)
		fmt.Printf("%s %s destinations=%d max_ttl=%s\n", principal.ID, openSSHEd25519Fingerprint(key), len(principal.Destinations), principal.MaxTTL)
	}
	return 0
}

func cmdSocksPrincipalShow(args []string) int {
	leading, parseArgs := splitLeadingOperands(args, 2)
	fs := flag.NewFlagSet("socks-policy principal show", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(parseArgs); err != nil {
		return 2
	}
	operands := append(leading, fs.Args()...)
	if len(operands) != 2 {
		fmt.Fprintln(os.Stderr, "usage: wv socks-policy principal show POLICY.json ID [--json]")
		return 2
	}
	policy, err := socksproof.LoadPolicyFile(operands[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "socks-policy principal show: %v\n", err)
		return 1
	}
	principal, ok := findSocksPrincipal(policy, operands[1])
	if !ok {
		fmt.Fprintf(os.Stderr, "socks-policy principal show: principal %q not found\n", operands[1])
		return 1
	}
	if *jsonOut {
		return printJSON(principal)
	}
	key, _ := authproof.DecodePublicKey(principal.PublicKey)
	fmt.Printf("principal: %s\nfingerprint: %s\ncapabilities: %s\ndestinations: %s\nmax-ttl: %s\n",
		principal.ID, openSSHEd25519Fingerprint(key), strings.Join(principal.Capabilities, ","), strings.Join(principal.Destinations, ","), principal.MaxTTL)
	return 0
}

func cmdSocksPrincipalAdd(args []string) int {
	leading, parseArgs := splitLeadingOperands(args, 1)
	fs := flag.NewFlagSet("socks-policy principal add", flag.ContinueOnError)
	id := fs.String("id", "", "principal id")
	publicKey := fs.String("public-key", "", "inline Ed25519 public key")
	publicKeyFile := fs.String("public-key-file", "", "Ed25519 public-key file")
	maxTTL := fs.String("max-ttl", "30s", "maximum principal proof TTL")
	replacePrincipal := fs.Bool("replace", false, "replace an existing principal with the same id")
	out := fs.String("out", "", "write updated policy to file")
	inPlace := fs.Bool("in-place", false, "atomically replace the input policy")
	force := fs.Bool("force", false, "replace existing --out file")
	var destinations commaListFlag
	fs.Var(&destinations, "destination", "allowed HOST:PORT or glob; repeatable or comma-separated")
	fs.Var(&destinations, "destinations", "alias for --destination")
	if err := fs.Parse(parseArgs); err != nil {
		return 2
	}
	operands := append(leading, fs.Args()...)
	if len(operands) != 1 || strings.TrimSpace(*id) == "" || len(destinations) == 0 || (*inPlace && strings.TrimSpace(*out) != "") {
		fmt.Fprintln(os.Stderr, "usage: wv socks-policy principal add POLICY.json --id ID --public-key-file KEY --destination HOST:PORT [--replace] [--out FILE|--in-place]")
		return 2
	}
	input := operands[0]
	policy, err := socksproof.LoadPolicyFile(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "socks-policy principal add: %v\n", err)
		return 1
	}
	principal, err := buildSocksPolicyPrincipal(*id, *publicKey, *publicKeyFile, destinations, *maxTTL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "socks-policy principal add: %v\n", err)
		return 1
	}
	found := false
	for index := range policy.Principals {
		if policy.Principals[index].ID == principal.ID {
			if !*replacePrincipal {
				fmt.Fprintf(os.Stderr, "socks-policy principal add: principal %q already exists; use --replace\n", principal.ID)
				return 1
			}
			policy.Principals[index] = principal
			found = true
			break
		}
	}
	if !found {
		policy.Principals = append(policy.Principals, principal)
	}
	policy, err = socksproof.NormalizePolicy(policy)
	if err != nil {
		fmt.Fprintf(os.Stderr, "socks-policy principal add: %v\n", err)
		return 1
	}
	destination := strings.TrimSpace(*out)
	replaceOutput := *force
	if *inPlace {
		destination = input
		replaceOutput = true
	}
	return emitOrWriteSocksPolicy("socks-policy principal add", destination, policy, replaceOutput)
}

func cmdSocksPrincipalRemove(args []string) int {
	leading, parseArgs := splitLeadingOperands(args, 2)
	fs := flag.NewFlagSet("socks-policy principal remove", flag.ContinueOnError)
	out := fs.String("out", "", "write updated policy to file")
	inPlace := fs.Bool("in-place", false, "atomically replace the input policy")
	force := fs.Bool("force", false, "replace existing --out file")
	if err := fs.Parse(parseArgs); err != nil {
		return 2
	}
	operands := append(leading, fs.Args()...)
	if len(operands) != 2 || (*inPlace && strings.TrimSpace(*out) != "") {
		fmt.Fprintln(os.Stderr, "usage: wv socks-policy principal remove POLICY.json ID [--out FILE|--in-place]")
		return 2
	}
	input, id := operands[0], strings.TrimSpace(operands[1])
	policy, err := socksproof.LoadPolicyFile(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "socks-policy principal remove: %v\n", err)
		return 1
	}
	if len(policy.Principals) == 1 && policy.Principals[0].ID == id {
		fmt.Fprintln(os.Stderr, "socks-policy principal remove: a policy must retain at least one principal")
		return 1
	}
	removed := false
	filtered := make([]socksproof.PrincipalPolicy, 0, len(policy.Principals))
	for _, principal := range policy.Principals {
		if principal.ID == id {
			removed = true
			continue
		}
		filtered = append(filtered, principal)
	}
	if !removed {
		fmt.Fprintf(os.Stderr, "socks-policy principal remove: principal %q not found\n", id)
		return 1
	}
	policy.Principals = filtered
	policy, err = socksproof.NormalizePolicy(policy)
	if err != nil {
		fmt.Fprintf(os.Stderr, "socks-policy principal remove: %v\n", err)
		return 1
	}
	destination := strings.TrimSpace(*out)
	replaceOutput := *force
	if *inPlace {
		destination = input
		replaceOutput = true
	}
	return emitOrWriteSocksPolicy("socks-policy principal remove", destination, policy, replaceOutput)
}

func buildSocksPolicyPrincipal(id, publicKey, publicKeyFile string, destinations []string, maxTTL string) (socksproof.PrincipalPolicy, error) {
	key, err := loadEd25519PublicKey(publicKey, publicKeyFile)
	if err != nil {
		return socksproof.PrincipalPolicy{}, err
	}
	return socksproof.PrincipalPolicy{
		ID:           strings.TrimSpace(id),
		PublicKey:    authproof.EncodePublicKey(key),
		Capabilities: []string{socksproof.CapabilityConnect},
		Destinations: normalizedUniqueStrings(destinations),
		MaxTTL:       strings.TrimSpace(maxTTL),
	}, nil
}

func findSocksPrincipal(policy socksproof.Policy, id string) (socksproof.PrincipalPolicy, bool) {
	id = strings.TrimSpace(id)
	for _, principal := range policy.Principals {
		if principal.ID == id {
			return principal, true
		}
	}
	return socksproof.PrincipalPolicy{}, false
}

func emitOrWriteSocksPolicy(command, output string, policy socksproof.Policy, replace bool) int {
	normalized, err := socksproof.NormalizePolicy(policy)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", command, err)
		return 1
	}
	if strings.TrimSpace(output) == "" {
		if err := emitJSONArtifact(os.Stdout, normalized); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", command, err)
			return 1
		}
		return 0
	}
	if err := writeJSONArtifact(output, normalized, 0o600, replace); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", command, err)
		return 1
	}
	digest, _ := socksproof.PolicyDigest(normalized)
	fmt.Printf("%s: wrote %s\npolicy-sha256: %s\n", command, output, digest)
	return 0
}

func printSocksPrincipalUsage() {
	fmt.Print(`usage: wv socks-policy principal <command> [options]

Commands:
  list POLICY.json
  show POLICY.json ID
  add POLICY.json --id ID --public-key-file KEY --destination HOST:PORT
  remove POLICY.json ID
`)
}
