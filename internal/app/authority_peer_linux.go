//go:build linux

package app

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func peerUID(conn net.Conn) (string, bool) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return "", false
	}
	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return "", false
	}
	var uid uint32
	var found bool
	var controlErr error
	if err := rawConn.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			controlErr = err
			return
		}
		uid = cred.Uid
		found = true
	}); err != nil || controlErr != nil || !found {
		return "", false
	}
	return fmt.Sprintf("%d", uid), true
}
