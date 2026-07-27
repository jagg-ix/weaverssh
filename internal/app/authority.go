package app

import (
	"fmt"
	"os"

	"weaverssh/authproof"
)

type websocketAuthorityContext struct {
	X11Authenticated      bool
	AgentKeyProofVerified bool
	SameUID               bool
	PrincipalUID          string
	ComponentUID          string
}

func newWebSocketAuthorityContext(x11Authenticated bool) websocketAuthorityContext {
	uid := currentProcessUID()
	return websocketAuthorityContext{
		X11Authenticated: x11Authenticated,
		ComponentUID:     uid,
	}
}

func authorizeWebSocketSession(config AgentConfig, ctx websocketAuthorityContext) error {
	level := authproof.NormalizeSecurityLevel(config.Proof.SecurityLevel)
	decision, err := authproof.EvaluateAuthority(level, authproof.AuthorityEvidence{
		SameUID:               ctx.SameUID,
		X11CookieMatched:      ctx.X11Authenticated,
		AgentSocketPresent:    os.Getenv("SSH_AUTH_SOCK") != "",
		AgentKeyProofVerified: ctx.AgentKeyProofVerified,
		PrincipalUID:          ctx.PrincipalUID,
		ComponentUID:          ctx.ComponentUID,
	})
	if err != nil {
		return fmt.Errorf("authority rejected level=%s required=%v missing=%v notes=%v: %w", decision.Level, decision.Required, decision.Missing, decision.Notes, err)
	}
	return nil
}
