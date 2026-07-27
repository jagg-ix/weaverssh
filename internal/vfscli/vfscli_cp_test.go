package vfscli

import "testing"

func TestCpEndpointsAcceptsToSeparator(t *testing.T) {
	src, dst, err := cpEndpoints([]string{"./local.log", "to", "vfs::origin:/logdir/node"})
	if err != nil {
		t.Fatalf("cpEndpoints: %v", err)
	}
	if src != "./local.log" || dst != "vfs::origin:/logdir/node" {
		t.Fatalf("cpEndpoints=%q,%q", src, dst)
	}
}

func TestCpEndpointsRequiresTwoEndpoints(t *testing.T) {
	if _, _, err := cpEndpoints([]string{"one"}); err == nil {
		t.Fatal("expected missing endpoint error")
	}
	if _, _, err := cpEndpoints([]string{"one", "through", "two"}); err == nil {
		t.Fatal("expected unknown separator error")
	}
}

func TestCpEndpointsAcceptsScpStyleNodeReferences(t *testing.T) {
	src, dst, err := cpEndpoints([]string{"node2:/var/log/app-4g.log", "$HOME/app-4g.log"})
	if err != nil {
		t.Fatalf("cpEndpoints: %v", err)
	}
	if src != "node2:/var/log/app-4g.log" || dst != "$HOME/app-4g.log" {
		t.Fatalf("cpEndpoints=%q,%q", src, dst)
	}

	src, dst, err = cpEndpoints([]string{"/var/log/app-4g.log", "origin:~/app-4g.log"})
	if err != nil {
		t.Fatalf("cpEndpoints: %v", err)
	}
	if src != "/var/log/app-4g.log" || dst != "origin:~/app-4g.log" {
		t.Fatalf("cpEndpoints=%q,%q", src, dst)
	}
}
