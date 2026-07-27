package sessionroute

import (
	"testing"

	"weaverssh/sessionmux"
)

func TestUDPAssociationServiceIsRoutable(t *testing.T) {
	if !routableService(sessionmux.ServiceUDP) {
		t.Fatal("ServiceUDP is not routable")
	}
}
