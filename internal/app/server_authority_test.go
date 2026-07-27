package app

import (
	"errors"
	"testing"

	"weaverssh/authproof"
)

func TestValidateStandaloneServerAuthorityAllowsCompatOnly(t *testing.T) {
	cfg := ServerConfig{ProofMode: authproof.ProofModeOff, ProofSecurityLevel: authproof.SecurityLevelCompat}
	if err := validateStandaloneServerAuthority(cfg); err != nil {
		t.Fatalf("compat server policy should pass: %v", err)
	}
}

func TestValidateStandaloneServerAuthorityRejectsUnenforcedProofModes(t *testing.T) {
	cases := []ServerConfig{
		{ProofMode: authproof.ProofModeRequired, ProofSecurityLevel: authproof.SecurityLevelCompat},
		{ProofMode: authproof.ProofModeOff, ProofSecurityLevel: authproof.SecurityLevelSameUID},
		{ProofMode: authproof.ProofModeOff, ProofSecurityLevel: authproof.SecurityLevelX11Cookie},
		{ProofMode: authproof.ProofModeOff, ProofSecurityLevel: authproof.SecurityLevelAgentProof},
		{ProofMode: authproof.ProofModeOff, ProofSecurityLevel: authproof.SecurityLevelStrict},
	}
	for _, cfg := range cases {
		if err := validateStandaloneServerAuthority(cfg); !errors.Is(err, errStandaloneServerAuthorityUnsupported) {
			t.Fatalf("policy mode=%q level=%q should fail closed with unsupported authority error, got %v", cfg.ProofMode, cfg.ProofSecurityLevel, err)
		}
	}
}
