package app

import (
	"errors"
	"fmt"

	"weaverssh/authproof"
)

var errStandaloneServerAuthorityUnsupported = errors.New("standalone server authority policy unsupported")

func validateStandaloneServerAuthority(config ServerConfig) error {
	proof := authproof.RuntimeConfig{
		Mode:          config.ProofMode,
		SecurityLevel: config.ProofSecurityLevel,
	}.Normalized()
	if err := proof.ValidateMode(); err != nil {
		return err
	}
	if proof.Mode == authproof.ProofModeRequired {
		return fmt.Errorf("%w: wv-server does not consume signed authproof frames; use wv-agent for agent_proof/strict relay admission or leave --proof-mode=off", errStandaloneServerAuthorityUnsupported)
	}
	if proof.SecurityLevel != authproof.SecurityLevelCompat {
		return fmt.Errorf("%w: wv-server listens on TCP and cannot prove same-UID or key-backed local authority for security_level=%s", errStandaloneServerAuthorityUnsupported, proof.SecurityLevel)
	}
	return nil
}
