package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestSplitNodeSelectorExpr(t *testing.T) {
	got := splitNodeSelectorExpr("local,active + @linode linode-*")
	want := []string{"local", "active", "@linode", "linode-*"}
	if !slices.Equal(got, want) {
		t.Fatalf("splitNodeSelectorExpr=%v want %v", got, want)
	}
}

func TestStatusRequestsNodeSelection(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"-json"},
		{"--json"},
	} {
		if statusRequestsNodeSelection(args) {
			t.Fatalf("statusRequestsNodeSelection(%v)=true want false", args)
		}
	}
	for _, args := range [][]string{
		{"--help"},
		{"-h"},
		{"--local"},
		{"--all-nodes"},
		{"--nodes", "all"},
		{"--chain", "linodes"},
		{"--chain=1"},
		{"-l", "env=prod"},
		{"--selector=role=jump"},
		{"--nodes=local,active"},
		{"--node=linode-a"},
		{"-n", "@linode"},
	} {
		if !statusRequestsNodeSelection(args) {
			t.Fatalf("statusRequestsNodeSelection(%v)=false want true", args)
		}
	}
}

func TestBuildNodeStatusReportSelectors(t *testing.T) {
	t.Setenv("WEAVERSSH_CONNECTIONS_FILE", filepath.Join(t.TempDir(), "connections.json"))
	report := buildNodeStatusReport(sampleNodeStatusStore(), []string{"local,active,@edge"})
	if !report.OK {
		t.Fatalf("report should be OK: %+v", report)
	}
	if report.Scope != "mixed" {
		t.Fatalf("scope=%q want mixed", report.Scope)
	}
	if len(report.Nodes) != 3 {
		t.Fatalf("nodes=%d want 3: %+v", len(report.Nodes), report.Nodes)
	}
	if got := report.Nodes[0].Name; got != "local" {
		t.Fatalf("first node=%q want local", got)
	}
	byName := nodeStatusByName(report)
	if !byName["linode-b"].Active {
		t.Fatalf("linode-b should be active: %+v", byName["linode-b"])
	}
	if byName["linode-a"].Endpoint != "ssh://kb@203.0.113.10:22" {
		t.Fatalf("linode-a endpoint wrong: %+v", byName["linode-a"])
	}
	if byName["linode-a"].Status != "configured" {
		t.Fatalf("linode-a status wrong: %+v", byName["linode-a"])
	}
}

func TestBuildNodeStatusReportAllAndGlobDedupes(t *testing.T) {
	report := buildNodeStatusReport(sampleNodeStatusStore(), []string{"all", "linode-*"})
	if !report.OK {
		t.Fatalf("report should be OK: %+v", report)
	}
	if len(report.Nodes) != 4 {
		t.Fatalf("nodes=%d want local plus 3 profiles: %+v", len(report.Nodes), report.Nodes)
	}
	byName := nodeStatusByName(report)
	if got := byName["linode-a"].MatchedBy; !slices.Contains(got, "all") || !slices.Contains(got, "linode-*") {
		t.Fatalf("linode-a matched_by=%v want all and linode-*", got)
	}
}

func TestBuildNodeStatusReportChainSelector(t *testing.T) {
	report := buildNodeStatusReport(sampleNodeStatusStore(), []string{"chain/linodes"})
	if !report.OK {
		t.Fatalf("report should be OK: %+v", report)
	}
	if len(report.Nodes) != 3 {
		t.Fatalf("chain status nodes=%d want 3: %+v", len(report.Nodes), report.Nodes)
	}
	byName := nodeStatusByName(report)
	if _, ok := byName["local"]; !ok {
		t.Fatalf("local node missing from chain report: %+v", report.Nodes)
	}
	if _, ok := byName["linode-a"]; !ok {
		t.Fatalf("linode-a missing from chain report: %+v", report.Nodes)
	}
	if _, ok := byName["linode-b"]; !ok {
		t.Fatalf("linode-b missing from chain report: %+v", report.Nodes)
	}
}

func TestBuildNodeStatusReportKubernetesResourceRefs(t *testing.T) {
	report := buildNodeStatusReport(sampleNodeStatusStore(), []string{"node/linode-a,profile/linode-b"})
	if !report.OK {
		t.Fatalf("resource ref report should be OK: %+v", report)
	}
	byName := nodeStatusByName(report)
	if _, ok := byName["linode-a"]; !ok {
		t.Fatalf("node/linode-a did not resolve: %+v", report.Nodes)
	}
	if _, ok := byName["linode-b"]; !ok {
		t.Fatalf("profile/linode-b did not resolve: %+v", report.Nodes)
	}
}

func TestBuildNodeStatusReportLabelSelector(t *testing.T) {
	report := buildNodeStatusReport(sampleNodeStatusStore(), []string{"label:env=prod,role=jump"})
	if !report.OK {
		t.Fatalf("label selector should be OK: %+v", report)
	}
	byName := nodeStatusByName(report)
	if _, ok := byName["local"]; !ok {
		t.Fatalf("chain label selector should expand local: %+v", report.Nodes)
	}
	if _, ok := byName["linode-a"]; !ok {
		t.Fatalf("chain/profile label selector should include linode-a: %+v", report.Nodes)
	}
	if _, ok := byName["linode-b"]; !ok {
		t.Fatalf("chain label selector should expand linode-b: %+v", report.Nodes)
	}
}

func TestLabelSelectorOperators(t *testing.T) {
	labels := map[string]string{"env": "prod", "role": "jump"}
	if !labelSelectorMatches(labels, []string{"linode"}, "env in (prod,staging),role!=endpoint,tag=linode") {
		t.Fatal("expected in/not-equals/tag selector to match")
	}
	if labelSelectorMatches(labels, nil, "env=dev") {
		t.Fatal("env=dev should not match")
	}
	if labelSelectorMatches(labels, nil, "!env") {
		t.Fatal("!env should not match when env exists")
	}
}

func TestBuildNodeStatusReportMissingSelector(t *testing.T) {
	report := buildNodeStatusReport(sampleNodeStatusStore(), []string{"missing-node"})
	if report.OK {
		t.Fatalf("report OK=true want false: %+v", report)
	}
	if !slices.Contains(report.Missing, "missing-node") {
		t.Fatalf("missing=%v want missing-node", report.Missing)
	}
}

func TestCmdNodeStatusLabelSelectorPreservesCommaExpression(t *testing.T) {
	t.Setenv("WEAVERSSH_CONNECTIONS_FILE", filepath.Join(t.TempDir(), "connections.json"))
	if err := saveConnStore(sampleNodeStatusStore()); err != nil {
		t.Fatalf("saveConnStore: %v", err)
	}
	rc, out := captureStdout(t, func() int {
		return cmdNodeStatus([]string{"-l", "env=prod,role=jump", "--json"})
	})
	if rc != 0 {
		t.Fatalf("cmdNodeStatus -l rc=%d output=%s", rc, out)
	}
	var report nodeStatusReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("decode node status json: %v\n%s", err, out)
	}
	if !slices.Equal(report.Selectors, []string{"label:env=prod,role=jump"}) {
		t.Fatalf("selectors=%v want single preserved label selector", report.Selectors)
	}
}

func TestCmdNodeStatusJSON(t *testing.T) {
	t.Setenv("WEAVERSSH_CONNECTIONS_FILE", filepath.Join(t.TempDir(), "connections.json"))
	if err := saveConnStore(sampleNodeStatusStore()); err != nil {
		t.Fatalf("saveConnStore: %v", err)
	}
	rc, out := captureStdout(t, func() int {
		return cmdNodeStatus([]string{"--nodes", "local,active", "--json"})
	})
	if rc != 0 {
		t.Fatalf("cmdNodeStatus rc=%d output=%s", rc, out)
	}
	var report nodeStatusReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("decode node status json: %v\n%s", err, out)
	}
	if report.Scope != "mixed" || len(report.Nodes) != 2 {
		t.Fatalf("decoded report wrong: %+v", report)
	}
	if !nodeStatusByName(report)["linode-b"].Active {
		t.Fatalf("active profile missing from decoded report: %+v", report)
	}
}

func sampleNodeStatusStore() ConnStore {
	return ConnStore{
		Active: "linode-b",
		Chains: []ConnChain{
			{Number: 1, Label: "linodes", Nodes: []string{"local", "linode-a", "linode-b"}, Tags: []string{"linode"}, Labels: map[string]string{"env": "prod", "role": "jump"}},
		},
		Profiles: []ConnProfile{
			{
				Name:               "linode-a",
				Version:            connLatestVersion,
				SSHHost:            "203.0.113.10",
				SSHUser:            "kb",
				SSHPort:            22,
				Adapter:            "openSSH",
				CredentialProvider: "sshAgent",
				NinePPort:          5640,
				Tags:               []string{"linode", "edge"},
				Labels:             map[string]string{"env": "prod", "role": "jump"},
				Capabilities:       capabilitiesForVersion(connLatestVersion),
			},
			{
				Name:               "linode-b",
				Version:            connLatestVersion,
				SSHHost:            "203.0.113.20",
				SSHUser:            "root",
				Adapter:            "openSSH",
				CredentialProvider: "identityFile",
				NinePPort:          5640,
				Tags:               []string{"linode", "core"},
				Labels:             map[string]string{"env": "prod", "role": "endpoint"},
				Capabilities:       capabilitiesForVersion(connLatestVersion),
			},
			{
				Name: "draft",
				Tags: []string{"draft"},
			},
		},
	}
}

func nodeStatusByName(report nodeStatusReport) map[string]nodeStatusItem {
	out := map[string]nodeStatusItem{}
	for _, node := range report.Nodes {
		out[node.Name] = node
	}
	return out
}

func captureStdout(t *testing.T, fn func() int) (int, string) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()
	rc := fn()
	if err := w.Close(); err != nil {
		t.Fatalf("close stdout pipe: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read stdout pipe: %v", err)
	}
	return rc, string(out)
}
