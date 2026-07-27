//go:build linux || darwin || freebsd

package app

import (
	"net"
	"os"
	"testing"
	"time"
)

func TestAuthorityContextFromUnixConnDetectsSameUID(t *testing.T) {
	socketFile, err := os.CreateTemp("/tmp", "wv-agent-*.sock")
	if err != nil {
		t.Fatalf("create temp socket path: %v", err)
	}
	path := socketFile.Name()
	_ = socketFile.Close()
	_ = os.Remove(path)
	t.Cleanup(func() { _ = os.Remove(path) })

	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errCh <- err
			return
		}
		accepted <- conn
	}()

	client, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatalf("dial unix: %v", err)
	}
	defer client.Close()

	var serverConn net.Conn
	select {
	case err := <-errCh:
		t.Fatalf("accept unix: %v", err)
	case serverConn = <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for unix accept")
	}
	defer serverConn.Close()

	ctx := authorityContextFromConn(true, serverConn)
	if ctx.PrincipalUID == "" {
		t.Fatal("expected peer UID evidence from Unix-domain socket")
	}
	if !ctx.SameUID {
		t.Fatalf("expected same UID evidence, got principal=%q component=%q", ctx.PrincipalUID, ctx.ComponentUID)
	}
	if !ctx.X11Authenticated {
		t.Fatal("authority context lost X11 authentication evidence")
	}
}
