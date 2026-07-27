package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
	"unicode"
)

type nodeSelectorList []string

func (l *nodeSelectorList) String() string {
	return strings.Join(*l, ",")
}

func (l *nodeSelectorList) Set(v string) error {
	for _, token := range splitNodeSelectorExpr(v) {
		*l = append(*l, token)
	}
	return nil
}

type rawSelectorList []string

func (l *rawSelectorList) String() string {
	return strings.Join(*l, ",")
}

func (l *rawSelectorList) Set(v string) error {
	v = strings.TrimSpace(v)
	if v != "" {
		*l = append(*l, v)
	}
	return nil
}

type nodeStatusReport struct {
	OK        bool             `json:"ok"`
	Scope     string           `json:"scope"`
	Selectors []string         `json:"selectors"`
	StorePath string           `json:"store_path"`
	Active    string           `json:"active,omitempty"`
	Nodes     []nodeStatusItem `json:"nodes"`
	Missing   []string         `json:"missing,omitempty"`
	Warnings  []string         `json:"warnings,omitempty"`
}

type nodeStatusItem struct {
	Name               string            `json:"name"`
	Kind               string            `json:"kind"`
	Status             string            `json:"status"`
	Active             bool              `json:"active,omitempty"`
	MatchedBy          []string          `json:"matched_by,omitempty"`
	Endpoint           string            `json:"endpoint,omitempty"`
	SSHHost            string            `json:"ssh_host,omitempty"`
	SSHUser            string            `json:"ssh_user,omitempty"`
	SSHPort            int               `json:"ssh_port,omitempty"`
	Adapter            string            `json:"adapter,omitempty"`
	CredentialProvider string            `json:"credential_provider,omitempty"`
	IdentityFile       string            `json:"identity_file,omitempty"`
	RepoRoot           string            `json:"repo_root,omitempty"`
	NinePPort          int               `json:"ninep_port,omitempty"`
	Tags               []string          `json:"tags,omitempty"`
	Labels             map[string]string `json:"labels,omitempty"`
	Capabilities       []ConnCapability  `json:"capabilities,omitempty"`
	Issues             []string          `json:"issues,omitempty"`
}

func cmdNodeStatus(args []string) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	var selectors nodeSelectorList
	var chainRefs nodeSelectorList
	var labelSelectors rawSelectorList
	jsonOut := fs.Bool("json", false, "emit JSON")
	localOnly := fs.Bool("local", false, "status for the local node only (same as --nodes local)")
	allNodes := fs.Bool("all-nodes", false, "status for local plus every configured connection profile")
	allAlias := fs.Bool("all", false, "alias for --all-nodes")
	fs.Var(&selectors, "nodes", "node selector expression: local, active, all, profiles, @tag, chain:LABEL, glob, or profile names")
	fs.Var(&selectors, "node", "single node selector; repeat for multiple nodes")
	fs.Var(&selectors, "n", "short alias for --node")
	fs.Var(&chainRefs, "chain", "stored chain label or number to expand into ordered nodes; repeatable")
	fs.Var(&labelSelectors, "selector", "Kubernetes-style label selector, e.g. env=prod,role=jump")
	fs.Var(&labelSelectors, "l", "short alias for --selector")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv status [--nodes EXPR | --node NAME ... | --local | --all-nodes] [--json]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Without a node selector, `wv status` keeps showing VFS/FUSE readiness.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Node selector sugar:")
		fmt.Fprintln(os.Stderr, "  local | self | .        local workstation node")
		fmt.Fprintln(os.Stderr, "  active | current        active connection profile")
		fmt.Fprintln(os.Stderr, "  all | *                 local plus all configured profiles")
		fmt.Fprintln(os.Stderr, "  profiles | remotes      all configured profiles, without local")
		fmt.Fprintln(os.Stderr, "  @tag                    profiles carrying TAG")
		fmt.Fprintln(os.Stderr, "  node/NAME | profile/NAME Kubernetes-style node/profile resource refs")
		fmt.Fprintln(os.Stderr, "  chain/linodes | chain:1 stored chain by label or number")
		fmt.Fprintln(os.Stderr, "  -l env=prod,role=jump   Kubernetes-style label selector")
		fmt.Fprintln(os.Stderr, "  linode-*                glob over profile names")
		fmt.Fprintln(os.Stderr, "  a,b+c                   comma, plus, or whitespace separated selectors")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Examples:")
		fmt.Fprintln(os.Stderr, "  wv status --local")
		fmt.Fprintln(os.Stderr, "  wv status --all-nodes")
		fmt.Fprintln(os.Stderr, "  wv status --nodes local,active")
		fmt.Fprintln(os.Stderr, "  wv status --chain chain/linodes")
		fmt.Fprintln(os.Stderr, "  wv status -l env=prod,role=jump")
		fmt.Fprintln(os.Stderr, "  wv status --nodes @linode")
		fmt.Fprintln(os.Stderr, "  wv status --nodes 'linode-*'")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	if *localOnly {
		selectors = append(selectors, "local")
	}
	if *allNodes || *allAlias {
		selectors = append(selectors, "all")
	}
	for _, ref := range chainRefs {
		selectors = append(selectors, "chain:"+ref)
	}
	for _, sel := range labelSelectors {
		selectors = append(selectors, "label:"+sel)
	}
	if len(selectors) == 0 {
		selectors = append(selectors, "local")
	}

	store, err := loadConnStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "status: %v\n", err)
		return 1
	}
	report := buildNodeStatusReport(store, selectors)
	if *jsonOut {
		return printJSON(report)
	}
	printNodeStatusReport(report)
	if !report.OK {
		return 1
	}
	return 0
}

func statusRequestsNodeSelection(args []string) bool {
	for _, arg := range args {
		switch {
		case arg == "--help" || arg == "-h" || arg == "help":
			return true
		case arg == "--local" || arg == "-local":
			return true
		case arg == "--all-nodes" || arg == "-all-nodes" || arg == "--all" || arg == "-all":
			return true
		case arg == "--nodes" || arg == "-nodes" || arg == "--node" || arg == "-node" || arg == "-n" || arg == "--chain" || arg == "-chain" || arg == "--selector" || arg == "-l":
			return true
		case strings.HasPrefix(arg, "--nodes=") || strings.HasPrefix(arg, "-nodes="):
			return true
		case strings.HasPrefix(arg, "--node=") || strings.HasPrefix(arg, "-node=") || strings.HasPrefix(arg, "-n="):
			return true
		case strings.HasPrefix(arg, "--chain=") || strings.HasPrefix(arg, "-chain="):
			return true
		case strings.HasPrefix(arg, "--selector=") || strings.HasPrefix(arg, "-l="):
			return true
		}
	}
	return false
}

func splitNodeSelectorExpr(expr string) []string {
	fields := strings.FieldsFunc(expr, func(r rune) bool {
		return r == ',' || r == '+' || unicode.IsSpace(r)
	})
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field != "" {
			out = append(out, field)
		}
	}
	return out
}

func buildNodeStatusReport(store ConnStore, selectors []string) nodeStatusReport {
	sortProfiles(store.Profiles)
	report := nodeStatusReport{
		OK:        true,
		Selectors: append([]string(nil), selectors...),
		StorePath: connectionsStorePath(),
		Active:    strings.TrimSpace(store.Active),
	}
	seen := map[string]int{}
	add := func(item nodeStatusItem, selector string) {
		key := item.Kind + ":" + item.Name
		if i, ok := seen[key]; ok {
			report.Nodes[i].MatchedBy = appendUnique(report.Nodes[i].MatchedBy, selector)
			return
		}
		item.MatchedBy = appendUnique(item.MatchedBy, selector)
		seen[key] = len(report.Nodes)
		report.Nodes = append(report.Nodes, item)
	}
	addLocal := func(selector string) {
		add(localNodeStatus(), selector)
	}
	addProfile := func(profile ConnProfile, selector string) {
		add(profileNodeStatus(profile, store.Active), selector)
	}
	addAllProfiles := func(selector string) {
		if len(store.Profiles) == 0 {
			report.Warnings = appendUnique(report.Warnings, selector+": no configured profiles")
			return
		}
		for _, profile := range store.Profiles {
			addProfile(profile, selector)
		}
	}
	addNodeName := func(name string, selector string) {
		name = normalizeNodeRef(name)
		switch strings.ToLower(name) {
		case "local", "self", ".", "origin", "workstation":
			addLocal(selector)
			return
		}
		profile, _, ok := findProfile(store, name)
		if !ok {
			report.Missing = appendUnique(report.Missing, selector+": node "+name+" not found")
			return
		}
		addProfile(profile, selector)
	}
	addChain := func(ref string, selector string) {
		chain, _, ok := resolveChain(store, ref)
		if !ok {
			report.Missing = appendUnique(report.Missing, selector)
			return
		}
		if len(chain.Nodes) == 0 {
			report.Missing = appendUnique(report.Missing, selector+": chain has no nodes")
			return
		}
		for _, node := range chain.Nodes {
			addNodeName(node, selector)
		}
	}

	for _, raw := range selectors {
		if strings.HasPrefix(strings.ToLower(raw), "label:") {
			applyLabelSelector(raw, strings.TrimPrefix(raw, "label:"), store, addProfile, addChain, &report)
			continue
		}
		for _, selector := range splitNodeSelectorExpr(raw) {
			lower := strings.ToLower(selector)
			switch lower {
			case "local", "self", ".", "origin", "workstation":
				addLocal(selector)
			case "all", "*":
				addLocal(selector)
				addAllProfiles(selector)
			case "profile", "profiles", "remote", "remotes", "connection", "connections":
				addAllProfiles(selector)
			case "active", "current", "@active":
				if strings.TrimSpace(store.Active) == "" {
					report.Missing = appendUnique(report.Missing, selector+": no active profile")
					continue
				}
				profile, _, ok := findProfile(store, store.Active)
				if !ok {
					report.Missing = appendUnique(report.Missing, selector+": active profile "+store.Active+" not found")
					continue
				}
				addProfile(profile, selector)
			default:
				if strings.HasPrefix(lower, "node/") || strings.HasPrefix(lower, "nodes/") || strings.HasPrefix(lower, "profile/") || strings.HasPrefix(lower, "profiles/") {
					addNodeName(selector, selector)
					continue
				}
				if strings.HasPrefix(lower, "chain/") || strings.HasPrefix(lower, "chains/") {
					addChain(selector, selector)
					continue
				}
				if strings.HasPrefix(lower, "chain:") || strings.HasPrefix(lower, "chains:") {
					ref := selector[strings.Index(selector, ":")+1:]
					addChain(ref, selector)
					continue
				}
				if strings.HasPrefix(selector, "#") {
					addChain(strings.TrimPrefix(selector, "#"), selector)
					continue
				}
				if strings.HasPrefix(selector, "@") {
					tag := strings.TrimPrefix(selector, "@")
					matched := false
					for _, profile := range store.Profiles {
						if profileHasTag(profile, tag) {
							addProfile(profile, selector)
							matched = true
						}
					}
					if !matched {
						report.Missing = appendUnique(report.Missing, selector)
					}
					continue
				}
				if hasGlob(selector) {
					matched := false
					for _, profile := range store.Profiles {
						ok, err := path.Match(selector, profile.Name)
						if err != nil {
							report.Missing = appendUnique(report.Missing, selector+": invalid glob")
							matched = true
							break
						}
						if ok {
							addProfile(profile, selector)
							matched = true
						}
					}
					if !matched {
						report.Missing = appendUnique(report.Missing, selector)
					}
					continue
				}
				profile, _, ok := findProfile(store, selector)
				if !ok {
					report.Missing = appendUnique(report.Missing, selector)
					continue
				}
				addProfile(profile, selector)
			}
		}
	}

	if len(report.Nodes) == 0 {
		report.Warnings = appendUnique(report.Warnings, "no nodes selected")
	}
	if len(report.Missing) > 0 {
		report.OK = false
	}
	report.Scope = summarizeNodeScope(report.Nodes)
	return report
}

func localNodeStatus() nodeStatusItem {
	repo := repoRootOrCwd()
	issues := []string{}
	if _, err := os.Stat(repo); err != nil {
		issues = append(issues, "repo root not accessible: "+err.Error())
	}
	status := "ready"
	if len(issues) > 0 {
		status = "needs_attention"
	}
	return nodeStatusItem{
		Name:     "local",
		Kind:     "local",
		Status:   status,
		RepoRoot: repo,
		Issues:   issues,
	}
}

func profileNodeStatus(profile ConnProfile, active string) nodeStatusItem {
	issues := []string{}
	if strings.TrimSpace(profile.SSHHost) == "" {
		issues = append(issues, "ssh_host missing")
	}
	if strings.TrimSpace(profile.Name) == "" {
		issues = append(issues, "profile name missing")
	}
	status := "configured"
	if len(issues) > 0 {
		status = "incomplete"
	}
	return nodeStatusItem{
		Name:               profile.Name,
		Kind:               "profile",
		Status:             status,
		Active:             profile.Name != "" && profile.Name == active,
		Endpoint:           profileEndpoint(profile),
		SSHHost:            profile.SSHHost,
		SSHUser:            profile.SSHUser,
		SSHPort:            portOrDefault(profile.SSHPort),
		Adapter:            profile.Adapter,
		CredentialProvider: profile.CredentialProvider,
		IdentityFile:       profile.IdentityFile,
		RepoRoot:           profile.RepoRoot,
		NinePPort:          profile.NinePPort,
		Tags:               append([]string(nil), profile.Tags...),
		Labels:             cloneLabels(profile.Labels),
		Capabilities:       append([]ConnCapability(nil), profile.Capabilities...),
		Issues:             issues,
	}
}

func profileEndpoint(profile ConnProfile) string {
	host := strings.TrimSpace(profile.SSHHost)
	if host == "" {
		return ""
	}
	userHost := host
	if user := strings.TrimSpace(profile.SSHUser); user != "" {
		userHost = user + "@" + host
	}
	return fmt.Sprintf("ssh://%s:%d", userHost, portOrDefault(profile.SSHPort))
}

func profileHasTag(profile ConnProfile, tag string) bool {
	tag = strings.TrimSpace(strings.TrimPrefix(tag, "@"))
	if tag == "" {
		return false
	}
	for _, existing := range profile.Tags {
		if strings.EqualFold(strings.TrimSpace(existing), tag) {
			return true
		}
	}
	return false
}

func hasGlob(selector string) bool {
	return strings.ContainsAny(selector, "*?[")
}

func summarizeNodeScope(nodes []nodeStatusItem) string {
	if len(nodes) == 0 {
		return "empty"
	}
	local := 0
	profiles := 0
	for _, node := range nodes {
		switch node.Kind {
		case "local":
			local++
		case "profile":
			profiles++
		}
	}
	switch {
	case local > 0 && profiles > 0:
		return "mixed"
	case local > 0:
		return "local"
	case profiles > 0:
		return "profiles"
	default:
		return "unknown"
	}
}

func printNodeStatusReport(report nodeStatusReport) {
	fmt.Printf("scope:    %s\n", report.Scope)
	fmt.Printf("store:    %s\n", report.StorePath)
	if report.Active != "" {
		fmt.Printf("active:   %s\n", report.Active)
	}
	if len(report.Selectors) > 0 {
		fmt.Printf("selector: %s\n", strings.Join(report.Selectors, ","))
	}
	if len(report.Nodes) == 0 {
		fmt.Println("nodes:    none")
	} else {
		fmt.Println("nodes:")
		for _, node := range report.Nodes {
			active := ""
			if node.Active {
				active = " active"
			}
			fmt.Printf("  - %s [%s] %s%s\n", node.Name, node.Kind, node.Status, active)
			if node.Endpoint != "" {
				fmt.Printf("    endpoint: %s\n", node.Endpoint)
			}
			if node.RepoRoot != "" {
				fmt.Printf("    repo:     %s\n", node.RepoRoot)
			}
			if node.Adapter != "" || node.CredentialProvider != "" {
				fmt.Printf("    adapter:  %s  credential: %s\n", orDash(node.Adapter), orDash(node.CredentialProvider))
			}
			if len(node.Tags) > 0 {
				fmt.Printf("    tags:     %s\n", strings.Join(node.Tags, ","))
			}
			if len(node.Labels) > 0 {
				fmt.Printf("    labels:   %s\n", formatLabels(node.Labels))
			}
			if len(node.Issues) > 0 {
				fmt.Printf("    issues:   %s\n", strings.Join(node.Issues, "; "))
			}
		}
	}
	if len(report.Warnings) > 0 {
		sort.Strings(report.Warnings)
		fmt.Printf("warnings: %s\n", strings.Join(report.Warnings, "; "))
	}
	if len(report.Missing) > 0 {
		sort.Strings(report.Missing)
		fmt.Printf("missing:  %s\n", strings.Join(report.Missing, "; "))
	}
}

func applyLabelSelector(selectorToken string, selector string, store ConnStore, addProfile func(ConnProfile, string), addChain func(string, string), report *nodeStatusReport) {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		report.Missing = appendUnique(report.Missing, selectorToken+": empty selector")
		return
	}
	matched := false
	for _, profile := range store.Profiles {
		if labelSelectorMatches(profile.Labels, profile.Tags, selector) {
			addProfile(profile, selectorToken)
			matched = true
		}
	}
	for _, chain := range store.Chains {
		if labelSelectorMatches(chain.Labels, chain.Tags, selector) {
			addChain(chain.Label, selectorToken)
			matched = true
		}
	}
	if !matched {
		report.Missing = appendUnique(report.Missing, selectorToken)
	}
}

func labelSelectorMatches(labels map[string]string, tags []string, selector string) bool {
	for _, req := range splitSelectorRequirements(selector) {
		if !labelRequirementMatches(labels, tags, req) {
			return false
		}
	}
	return true
}

func splitSelectorRequirements(selector string) []string {
	var out []string
	start, depth := 0, 0
	for i, r := range selector {
		switch r {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				part := strings.TrimSpace(selector[start:i])
				if part != "" {
					out = append(out, part)
				}
				start = i + 1
			}
		}
	}
	part := strings.TrimSpace(selector[start:])
	if part != "" {
		out = append(out, part)
	}
	return out
}

func labelRequirementMatches(labels map[string]string, tags []string, req string) bool {
	req = strings.TrimSpace(req)
	if req == "" {
		return true
	}
	if strings.HasPrefix(req, "!") {
		return !labelExists(labels, tags, strings.TrimSpace(strings.TrimPrefix(req, "!")))
	}
	lower := strings.ToLower(req)
	for _, op := range []string{" notin ", " in "} {
		if i := strings.Index(lower, op); i >= 0 {
			key := strings.TrimSpace(req[:i])
			values := selectorSetValues(req[i+len(op):])
			match := labelValueIn(labels, tags, key, values)
			if strings.TrimSpace(op) == "notin" {
				return !match
			}
			return match
		}
	}
	if key, value, ok := strings.Cut(req, "!="); ok {
		return !labelValueEquals(labels, tags, strings.TrimSpace(key), strings.TrimSpace(value))
	}
	if key, value, ok := strings.Cut(req, "=="); ok {
		return labelValueEquals(labels, tags, strings.TrimSpace(key), strings.TrimSpace(value))
	}
	if key, value, ok := strings.Cut(req, "="); ok {
		return labelValueEquals(labels, tags, strings.TrimSpace(key), strings.TrimSpace(value))
	}
	return labelExists(labels, tags, req)
}

func selectorSetValues(raw string) []string {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "(")
	raw = strings.TrimSuffix(raw, ")")
	return splitLabelCSV(raw)
}

func labelExists(labels map[string]string, tags []string, key string) bool {
	key = strings.TrimSpace(key)
	if key == "tag" || key == "tags" {
		return len(tags) > 0
	}
	_, ok := labels[key]
	return ok
}

func labelValueEquals(labels map[string]string, tags []string, key, value string) bool {
	if key == "tag" || key == "tags" {
		for _, tag := range tags {
			if tag == value {
				return true
			}
		}
		return false
	}
	return labels[key] == value
}

func labelValueIn(labels map[string]string, tags []string, key string, values []string) bool {
	for _, value := range values {
		if labelValueEquals(labels, tags, key, value) {
			return true
		}
	}
	return false
}

func cloneLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	out := map[string]string{}
	for k, v := range labels {
		out[k] = v
	}
	return out
}

func appendUnique(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
