package sessionroute

import (
	"testing"

	"weaverssh/sessionmux"
)

func TestProgrammableServicesAreRoutable(t *testing.T) {
	for _, service := range []sessionmux.ServiceID{sessionmux.ServiceExec, sessionmux.ServiceEvents} {
		if !routableService(service) {
			t.Fatalf("service %s is not routable", service)
		}
	}
}
