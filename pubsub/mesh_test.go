package pubsub

import "testing"

func TestMeshEnvelopeForwardingUsesNodeScopedTopics(t *testing.T) {
	event := NewEvent("status", "runtime", "ready", map[string]string{"plane": "ok"})
	env, err := NewMeshEnvelope("weaverssh", "linode-chain", "alice", event, 4)
	if err != nil {
		t.Fatalf("NewMeshEnvelope: %v", err)
	}
	if env.Topic != "weaverssh/chains/linode-chain/nodes/alice/runtime/status" {
		t.Fatalf("unexpected origin topic: %s", env.Topic)
	}
	jump, err := env.ForwardTo("weaverssh", "linode-a")
	if err != nil {
		t.Fatalf("ForwardTo linode-a: %v", err)
	}
	if jump.NodeID != "linode-a" || jump.OriginNodeID != "alice" || jump.Hop != 1 {
		t.Fatalf("forward metadata wrong: %+v", jump)
	}
	if jump.Topic != "weaverssh/chains/linode-chain/nodes/linode-a/runtime/status" {
		t.Fatalf("unexpected forwarded topic: %s", jump.Topic)
	}
	if len(jump.Path) != 2 || jump.Path[0] != "alice" || jump.Path[1] != "linode-a" {
		t.Fatalf("path wrong: %v", jump.Path)
	}
}

func TestMeshEnvelopeRejectsLoopsAndHopOverflow(t *testing.T) {
	event := NewEvent("status", "runtime", "ready", nil)
	env, err := NewMeshEnvelope("weaverssh", "chain", "alice", event, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.ForwardTo("weaverssh", "alice"); err == nil {
		t.Fatal("expected loop detection")
	}
	jump, err := env.ForwardTo("weaverssh", "jump")
	if err != nil {
		t.Fatalf("first forward should fit max hops: %v", err)
	}
	if _, err := jump.ForwardTo("weaverssh", "target"); err == nil {
		t.Fatal("expected max-hop rejection")
	}
}

func TestRouteRulesAllowDenyAndRewrite(t *testing.T) {
	event := NewEvent("fault", "authproof", "denied", nil)
	env, err := NewMeshEnvelope("weaverssh", "chain", "alice", event, 4)
	if err != nil {
		t.Fatal(err)
	}

	deny := RouteRule{ID: "deny-auth", Action: RuleDeny, FromNode: "alice", ToNode: "jump", TopicFilter: "weaverssh/chains/chain/#"}
	decision, err := DecideRoute(env, "jump", []RouteRule{deny})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed || decision.RuleID != "deny-auth" {
		t.Fatalf("deny decision wrong: %+v", decision)
	}

	allow := RouteRule{ID: "allow-chain", Action: RuleAllow, FromNode: "alice", ToNode: "jump", TopicFilter: "weaverssh/chains/chain/#"}
	forwarded, decision, err := ForwardWithRules("weaverssh", env, "jump", []RouteRule{allow})
	if err != nil {
		t.Fatalf("allow forward: %v decision=%+v", err, decision)
	}
	if !decision.Allowed || forwarded.NodeID != "jump" {
		t.Fatalf("allow result wrong: decision=%+v env=%+v", decision, forwarded)
	}

	rewrite := RouteRule{
		ID:           "rewrite-status",
		Action:       RuleRewrite,
		FromNode:     "alice",
		ToNode:       "jump",
		TopicFilter:  "weaverssh/chains/chain/#",
		RewriteTopic: "weaverssh/chains/chain/nodes/jump/audit/fault",
	}
	forwarded, decision, err = ForwardWithRules("weaverssh", env, "jump", []RouteRule{rewrite})
	if err != nil {
		t.Fatalf("rewrite forward: %v", err)
	}
	if !decision.Allowed || forwarded.Topic != rewrite.RewriteTopic {
		t.Fatalf("rewrite result wrong: decision=%+v env=%+v", decision, forwarded)
	}
}

func TestDefaultChainRules(t *testing.T) {
	rules, err := DefaultChainRules("weaverssh", "linode-chain", []string{"alice", "linode-a", "linode-b"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("rules=%d want 2", len(rules))
	}
	if rules[0].FromNode != "alice" || rules[0].ToNode != "linode-a" || rules[0].TopicFilter != "weaverssh/chains/linode-chain/#" {
		t.Fatalf("first rule wrong: %+v", rules[0])
	}
	filter, err := ChainSubscribeFilter("weaverssh", "linode-chain")
	if err != nil {
		t.Fatal(err)
	}
	if filter != "weaverssh/chains/linode-chain/#" {
		t.Fatalf("filter=%q", filter)
	}
}

func TestChainRulesForSupportedSchemes(t *testing.T) {
	nodes := []string{"alise", "linode-a", "linode-b"}

	oneOne, err := ChainRulesForScheme("weaverssh", "linodes", nodes, SchemeOneOne)
	if err != nil {
		t.Fatalf("one-one rules: %v", err)
	}
	if len(oneOne) != 2 || oneOne[0].OriginNode != "alise" || oneOne[1].OriginNode != "alise" {
		t.Fatalf("one-one should be directional from first node: %+v", oneOne)
	}

	oneMany, err := ChainRulesForScheme("weaverssh", "linodes", nodes, SchemeOneMany)
	if err != nil {
		t.Fatalf("one-many rules: %v", err)
	}
	if len(oneMany) != 2 || oneMany[0].ID != "one-many-alise-to-linode-a" || oneMany[1].OriginNode != "alise" {
		t.Fatalf("one-many should fan out from first node: %+v", oneMany)
	}

	manyToMany, err := ChainRulesForScheme("weaverssh", "linodes", nodes, SchemeManyToMany)
	if err != nil {
		t.Fatalf("many-to-many rules: %v", err)
	}
	if len(manyToMany) != 4 {
		t.Fatalf("many-to-many should generate bidirectional adjacent rules, got %d", len(manyToMany))
	}
	if manyToMany[0].FromNode != "alise" || manyToMany[0].ToNode != "linode-a" {
		t.Fatalf("first many-to-many rule wrong: %+v", manyToMany[0])
	}
	if manyToMany[1].FromNode != "linode-a" || manyToMany[1].ToNode != "alise" {
		t.Fatalf("reverse many-to-many rule wrong: %+v", manyToMany[1])
	}
	for _, rule := range manyToMany {
		if rule.OriginNode != "" {
			t.Fatalf("many-to-many should allow any origin, rule=%+v", rule)
		}
	}
}

func TestRouteRulesCanScopeOrigin(t *testing.T) {
	event := NewEvent("status", "runtime", "ready", nil)
	env, err := NewMeshEnvelope("weaverssh", "linodes", "alise", event, 4)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := ChainRulesForScheme("weaverssh", "linodes", []string{"alise", "linode-a", "linode-b"}, SchemeOneMany)
	if err != nil {
		t.Fatal(err)
	}
	forwarded, decision, err := ForwardWithRules("weaverssh", env, "linode-a", rules)
	if err != nil || !decision.Allowed {
		t.Fatalf("origin alise should be allowed: decision=%+v err=%v", decision, err)
	}
	if forwarded.OriginNodeID != "alise" || forwarded.NodeID != "linode-a" {
		t.Fatalf("forwarded metadata wrong: %+v", forwarded)
	}

	other, err := NewMeshEnvelope("weaverssh", "linodes", "linode-a", event, 4)
	if err != nil {
		t.Fatal(err)
	}
	decision, err = DecideRoute(other, "linode-b", rules)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed {
		t.Fatalf("one-many rules should deny non-root origin: %+v", decision)
	}
}

func TestParseMeshSchemeRejectsUnknown(t *testing.T) {
	if _, err := ParseMeshScheme("broadcast-all"); err == nil {
		t.Fatal("expected unknown scheme to fail")
	}
}

func TestRulesUseOnlyAdjacentLinks(t *testing.T) {
	nodes := []string{"origin", "node1", "node2"}
	links, err := ChainLinks(nodes)
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 2 {
		t.Fatalf("links=%d want 2", len(links))
	}
	if links[0].From != "origin" || links[0].To != "node1" || links[0].Transport != SingleSSHSocketChainMode {
		t.Fatalf("first link wrong: %+v", links[0])
	}
	rules, err := ChainRulesForScheme("weaverssh", "chain", nodes, SchemeManyToMany)
	if err != nil {
		t.Fatal(err)
	}
	if !RulesUseOnlyAdjacentLinks(rules, links) {
		t.Fatalf("generated rules must stay on adjacent links: %+v links=%+v", rules, links)
	}
	direct := append([]RouteRule{}, rules...)
	direct = append(direct, RouteRule{ID: "bad-direct", Action: RuleAllow, FromNode: "origin", ToNode: "node2", TopicFilter: "weaverssh/chains/chain/#"})
	if RulesUseOnlyAdjacentLinks(direct, links) {
		t.Fatal("direct origin->node2 rule must violate the single socket chain constraint")
	}
}
