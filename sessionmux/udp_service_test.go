package sessionmux

import "testing"

func TestUDPServiceIsAppendedWithoutRenumberingExistingServices(t *testing.T) {
	if ServiceControl != 1 || ServiceFS != 2 || ServiceTCP != 3 || ServiceExec != 4 || ServiceEvents != 5 || ServiceUDP != 6 || ServiceTerminal != 7 {
		t.Fatalf("service IDs changed: control=%d fs=%d tcp=%d exec=%d events=%d udp=%d terminal=%d", ServiceControl, ServiceFS, ServiceTCP, ServiceExec, ServiceEvents, ServiceUDP, ServiceTerminal)
	}
	if !ServiceUDP.Valid() || ServiceUDP.String() != "udp" {
		t.Fatalf("UDP service invalid: valid=%t string=%q", ServiceUDP.Valid(), ServiceUDP.String())
	}
	if !ServiceTerminal.Valid() || ServiceTerminal.String() != "terminal" {
		t.Fatalf("terminal service invalid: valid=%t string=%q", ServiceTerminal.Valid(), ServiceTerminal.String())
	}
}
