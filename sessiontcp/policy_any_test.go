package sessiontcp

import "testing"

func TestAllowsAnyRequiresExplicitStarStar(t *testing.T) {
	for _, raw := range []string{
		"*:443",
		"example.internal:*",
		"*.internal:*",
		"*:443,example.internal:*",
	} {
		allow, err := ParseAllowlist(raw)
		if err != nil { t.Fatal(err) }
		if allow.AllowsAny() { t.Fatalf("%q unexpectedly permits wildcard BIND", raw) }
	}
	allow, err := ParseAllowlist("127.0.0.1:22,*:*")
	if err != nil { t.Fatal(err) }
	if !allow.AllowsAny() { t.Fatal("explicit *:* did not permit wildcard BIND") }
}
