package contract

import "testing"

func TestNormalizeRemotePlatform(t *testing.T) {
	cases := map[string]string{
		"linux":             "linux-generic",
		"linux-headless":    "linux-headless",
		"linux without gui": "linux-headless",
		"kde":               "linux-gui",
		"darwin":            "macos",
		"freebsd":           "freebsd-generic",
		"freebsd-gui":       "freebsd-gui",
		"openbsd":           "openbsd",
		"z/os":              "zos",
		"sunos":             "solaris",
		"posix":             "generic",
		"unknown":           "auto",
	}
	for input, want := range cases {
		got := NormalizeRemotePlatform(input)
		if got != want {
			t.Fatalf("NormalizeRemotePlatform(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestParseHostSpecBoundaries(t *testing.T) {
	type tc struct {
		spec      string
		wantLabel string
		wantHost  string
		wantErr   string
	}
	cases := []tc{
		{spec: "203.0.113.20", wantLabel: "203.0.113.20", wantHost: "203.0.113.20"},
		{spec: "linode-a=203.0.113.10", wantLabel: "linode-a", wantHost: "203.0.113.10"},
		{spec: " =203.0.113.10", wantLabel: "203.0.113.10", wantHost: "203.0.113.10"},
		{spec: "broken=", wantErr: "missing_host"},
		{spec: "   ", wantErr: "missing_host"},
	}
	for _, c := range cases {
		gotLabel, gotHost, err := ParseHostSpec(c.spec)
		if c.wantErr != "" {
			if err == nil || err.Error() != c.wantErr {
				t.Fatalf("ParseHostSpec(%q) err=%v, want %q", c.spec, err, c.wantErr)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ParseHostSpec(%q) unexpected err: %v", c.spec, err)
		}
		if gotLabel != c.wantLabel || gotHost != c.wantHost {
			t.Fatalf("ParseHostSpec(%q)=(%q,%q), want (%q,%q)", c.spec, gotLabel, gotHost, c.wantLabel, c.wantHost)
		}
	}
}

func TestBuildTarget(t *testing.T) {
	got, err := BuildTarget("", "203.0.113.20")
	if err != nil {
		t.Fatalf("BuildTarget unexpected err: %v", err)
	}
	if got != "root@203.0.113.20" {
		t.Fatalf("BuildTarget got %q", got)
	}
	_, err = BuildTarget("root", " ")
	if err == nil {
		t.Fatalf("BuildTarget expected missing_host error")
	}
}

func FuzzParseHostSpec(f *testing.F) {
	seeds := []string{
		"203.0.113.20",
		"linode-a=203.0.113.10",
		"broken=",
		"",
		"   ",
		"weird===token",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, spec string) {
		label, host, err := ParseHostSpec(spec)
		if err != nil {
			if err.Error() == "" {
				t.Fatalf("error must have message")
			}
			return
		}
		if host == "" {
			t.Fatalf("host cannot be empty when err is nil (spec=%q)", spec)
		}
		if label == "" {
			t.Fatalf("label cannot be empty when err is nil (spec=%q)", spec)
		}
	})
}
