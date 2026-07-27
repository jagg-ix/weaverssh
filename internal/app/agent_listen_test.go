package app

import "testing"

func TestParseAgentListenAddressSupportsTCPAndUnix(t *testing.T) {
	cases := []struct {
		input       string
		wantNetwork string
		wantAddress string
		wantPort    int
	}{
		{input: "localhost:6010", wantNetwork: "tcp", wantAddress: "localhost:6010", wantPort: 6010},
		{input: "tcp://0.0.0.0:6011", wantNetwork: "tcp", wantAddress: "0.0.0.0:6011", wantPort: 6011},
		{input: "6012", wantNetwork: "tcp", wantAddress: "localhost:6012", wantPort: 6012},
		{input: "unix:/tmp/weaverssh-agent.sock", wantNetwork: "unix", wantAddress: "/tmp/weaverssh-agent.sock"},
		{input: "unix:///tmp/weaverssh-agent.sock", wantNetwork: "unix", wantAddress: "/tmp/weaverssh-agent.sock"},
	}
	for _, tc := range cases {
		network, address, port, err := parseAgentListenAddress(tc.input)
		if err != nil {
			t.Fatalf("parse %q: %v", tc.input, err)
		}
		if network != tc.wantNetwork || address != tc.wantAddress || port != tc.wantPort {
			t.Fatalf("parse %q = (%q, %q, %d), want (%q, %q, %d)", tc.input, network, address, port, tc.wantNetwork, tc.wantAddress, tc.wantPort)
		}
	}
}

func TestParseAgentListenAddressRejectsInvalidInputs(t *testing.T) {
	for _, input := range []string{"", "localhost:not-a-port", "unix:"} {
		if _, _, _, err := parseAgentListenAddress(input); err == nil {
			t.Fatalf("parse %q should fail", input)
		}
	}
}

func TestNormalizeAgentInterfaceMode(t *testing.T) {
	cases := map[string]AgentInterfaceMode{
		"":             AgentInterfaceTCP,
		"tcp":          AgentInterfaceTCP,
		"unix":         AgentInterfaceUnix,
		"uds":          AgentInterfaceUnix,
		"library":      AgentInterfaceLibrary,
		"library-only": AgentInterfaceLibrary,
		"no-listener":  AgentInterfaceLibrary,
	}
	for input, want := range cases {
		got, err := normalizeAgentInterfaceMode(input)
		if err != nil {
			t.Fatalf("normalize %q: %v", input, err)
		}
		if got != want {
			t.Fatalf("normalize %q=%q, want %q", input, got, want)
		}
	}
	if _, err := normalizeAgentInterfaceMode("bluetooth"); err == nil {
		t.Fatal("unknown interface should fail")
	}
}

func TestParseAgentListenAddressSupportsLibraryOnly(t *testing.T) {
	network, address, port, err := parseAgentListenAddress("library-only")
	if err != nil {
		t.Fatalf("parse library-only: %v", err)
	}
	if network != "library" || address != "" || port != 0 {
		t.Fatalf("parse library-only=(%q,%q,%d), want (library,,0)", network, address, port)
	}
}

func TestValidateAgentInterfaceListenRejectsMixedModes(t *testing.T) {
	valid := []AgentConfig{
		{InterfaceMode: "tcp", ListenNetwork: "tcp", ListenAddr: "localhost:6000"},
		{InterfaceMode: "unix", ListenNetwork: "unix", ListenAddr: "/tmp/weaverssh-agent.sock"},
		{InterfaceMode: "library", ListenNetwork: "library"},
	}
	for _, config := range valid {
		if err := validateAgentInterfaceListen(config); err != nil {
			t.Fatalf("valid config rejected: %+v: %v", config, err)
		}
	}

	invalid := []AgentConfig{
		{InterfaceMode: "tcp", ListenNetwork: "unix", ListenAddr: "/tmp/weaverssh-agent.sock"},
		{InterfaceMode: "unix", ListenNetwork: "tcp", ListenAddr: "localhost:6000"},
		{InterfaceMode: "library", ListenNetwork: "tcp", ListenAddr: "localhost:6000"},
	}
	for _, config := range invalid {
		if err := validateAgentInterfaceListen(config); err == nil {
			t.Fatalf("invalid config accepted: %+v", config)
		}
	}
}
