package main

import "strings"

const sessionNodeNamespace = "node:"

// cmdFileVerbWithAliases is the compatibility entry point for broker-aware file
// commands. It shares the transactional dispatcher used by the public CLI.
func cmdFileVerbWithAliases(verb string, args []string) int {
	return cmdFileVerbTransactional(verb, args)
}

func normalizeSessionAliasArgs(args []string) []string {
	out := make([]string, len(args))
	for index, arg := range args { out[index] = normalizeSessionAliasOperand(arg) }
	return out
}

func normalizeSessionAliasOperand(raw string) string {
	if len(raw) < len(sessionNodeNamespace) || !strings.EqualFold(raw[:len(sessionNodeNamespace)], sessionNodeNamespace) { return raw }
	rest := raw[len(sessionNodeNamespace):]
	separator := strings.IndexByte(rest, ':')
	if separator <= 0 { return raw }
	node := strings.TrimSpace(rest[:separator])
	if node == "" { return raw }
	return node + rest[separator:]
}
