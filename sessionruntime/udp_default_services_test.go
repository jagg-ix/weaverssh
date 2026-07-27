package sessionruntime

import (
	"testing"

	"weaverssh/sessionmux"
)

func TestDynamicSessionDefaultsIncludeUDP(t *testing.T) {
	config := withDefaultServices(sessionmux.Config{})
	for _, service := range []sessionmux.ServiceID{
		sessionmux.ServiceControl,
		sessionmux.ServiceFS,
		sessionmux.ServiceTCP,
		sessionmux.ServiceExec,
		sessionmux.ServiceEvents,
		sessionmux.ServiceUDP,
	} {
		if !config.AllowedServices[service] {
			t.Fatalf("default dynamic-session policy does not allow %s", service)
		}
	}
}

func TestDynamicSessionPreservesExplicitServicePolicy(t *testing.T) {
	explicit := map[sessionmux.ServiceID]bool{
		sessionmux.ServiceControl: true,
		sessionmux.ServiceFS:      true,
	}
	config := withDefaultServices(sessionmux.Config{AllowedServices: explicit})
	if config.AllowedServices[sessionmux.ServiceUDP] {
		t.Fatal("explicit restrictive service policy was widened with UDP")
	}
	if len(config.AllowedServices) != len(explicit) {
		t.Fatalf("explicit policy changed: %v", config.AllowedServices)
	}
}
