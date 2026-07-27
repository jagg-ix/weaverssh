package app

import "testing"

func TestParseSocksAgentEndpointSupportsTCPAndUnix(t *testing.T) {
	cases := []struct {
		input       string
		wantNetwork string
		wantAddress string
	}{
		{input: "localhost:6000", wantNetwork: "tcp", wantAddress: "localhost:6000"},
		{input: "tcp://127.0.0.1:6001", wantNetwork: "tcp", wantAddress: "127.0.0.1:6001"},
		{input: "unix:/tmp/weaverssh-agent.sock", wantNetwork: "unix", wantAddress: "/tmp/weaverssh-agent.sock"},
		{input: "unix:///tmp/weaverssh-agent.sock", wantNetwork: "unix", wantAddress: "/tmp/weaverssh-agent.sock"},
	}
	for _, tc := range cases {
		network, address, err := parseSocksAgentEndpoint(tc.input)
		if err != nil {
			t.Fatalf("parse %q: %v", tc.input, err)
		}
		if network != tc.wantNetwork || address != tc.wantAddress {
			t.Fatalf("parse %q = (%q, %q), want (%q, %q)", tc.input, network, address, tc.wantNetwork, tc.wantAddress)
		}
	}
}

func TestParseSocksAgentEndpointRejectsEmptyInput(t *testing.T) {
	if _, _, err := parseSocksAgentEndpoint("  "); err == nil {
		t.Fatal("empty agent endpoint should fail")
	}
}
