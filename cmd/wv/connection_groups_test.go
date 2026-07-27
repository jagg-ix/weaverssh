package main

import (
	"strings"
	"testing"
)

func tier1Store() ConnStore {
	return ConnStore{
		Groups: []ConnGroup{{Name: "computes", Members: []string{"compute-1", "compute-2", "compute-3"}}},
	}
}

func tier1Chain() ConnChain {
	return ConnChain{Label: "path", Nodes: []string{"origin", "jump", "group:computes"}}
}

func TestResolvePathPinnedMember(t *testing.T) {
	got, err := resolvePath(tier1Store(), tier1Chain(), map[string]string{"computes": "compute-2"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "origin,jump,compute-2" {
		t.Fatalf("resolved path = %v", got)
	}
}

func TestResolvePathAmbiguousNeedsSelector(t *testing.T) {
	if _, err := resolvePath(tier1Store(), tier1Chain(), nil, nil, nil); err == nil {
		t.Fatal("expected ambiguity error for a multi-member group with no selector")
	}
}

func TestResolvePathRejectsNonMember(t *testing.T) {
	if _, err := resolvePath(tier1Store(), tier1Chain(), map[string]string{"computes": "rogue"}, nil, nil); err == nil {
		t.Fatal("expected error resolving to a non-member")
	}
}

func TestResolvePathExecResolver(t *testing.T) {
	// A resolver program receives WV_GROUP_MEMBERS and prints the chosen member.
	got, err := resolvePath(tier1Store(), tier1Chain(), nil, map[string]string{"computes": "exec:echo compute-3"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got[len(got)-1] != "compute-3" {
		t.Fatalf("exec resolver chose %q, path=%v", got[len(got)-1], got)
	}
}

func TestResolvePathSignedSetEnforced(t *testing.T) {
	signed := map[string]bool{"origin": true, "jump": true, "compute-1": true, "compute-2": true, "compute-3": true}
	if _, err := resolvePath(tier1Store(), tier1Chain(), map[string]string{"computes": "compute-2"}, nil, signed); err != nil {
		t.Fatalf("expected success when all members are signed: %v", err)
	}

	// A group member outside the signed set fails closed, even if the *chosen*
	// member is signed: the whole candidate set must be pre-authorized.
	rogueStore := ConnStore{Groups: []ConnGroup{{Name: "computes", Members: []string{"compute-1", "unsigned-x"}}}}
	rogueChain := ConnChain{Label: "path", Nodes: []string{"origin", "group:computes"}}
	if _, err := resolvePath(rogueStore, rogueChain, map[string]string{"computes": "compute-1"}, nil, signed); err == nil {
		t.Fatal("expected error: a group member is not in the signed node set")
	}
}
