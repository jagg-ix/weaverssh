//go:build !linux && !darwin && !freebsd

package app

import "net"

func peerUID(net.Conn) (string, bool) {
	return "", false
}
