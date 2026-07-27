package app

import (
	"strings"

	"weaverssh/socksproof"
)

const (
	EnvSocksProofPolicy = "WEAVERSSH_SOCKS_PROOF_POLICY"
	EnvTCPRequireProof  = "WEAVERSSH_TCP_REQUIRE_PROOF"
)

func LoadSocksProofVerifier(path string) (*socksproof.Verifier, error) {
	policy, err := socksproof.LoadPolicyFile(strings.TrimSpace(path))
	if err != nil {
		return nil, err
	}
	return socksproof.NewVerifier(policy)
}

func envBoolValue(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on", "required":
		return true
	default:
		return false
	}
}
