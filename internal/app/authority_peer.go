package app

import "net"

func authorityContextFromConn(x11Authenticated bool, conn net.Conn) websocketAuthorityContext {
	ctx := newWebSocketAuthorityContext(x11Authenticated)
	uid, ok := peerUID(conn)
	if !ok || uid == "" {
		return ctx
	}
	ctx.PrincipalUID = uid
	ctx.SameUID = ctx.ComponentUID != "" && uid == ctx.ComponentUID
	return ctx
}
