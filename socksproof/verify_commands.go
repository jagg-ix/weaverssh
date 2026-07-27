package socksproof

import (
	"strings"
	"time"
)

// VerifyCommandBundle reproduces identity and command authorization at the final
// owning node. Intermediate proxy verification is not trusted.
func (v *Verifier) VerifyCommandBundle(bundle Bundle, command byte, expectedNetwork, expectedAddress, expectedNode string, now time.Time) (PrincipalPolicy, error) {
	if v == nil {
		return PrincipalPolicy{}, ErrUnauthorized
	}
	expectedNode = strings.TrimSpace(expectedNode)
	if strings.TrimSpace(bundle.Challenge.SelectedNode) != expectedNode {
		return PrincipalPolicy{}, ErrInvalidProof
	}
	principal, err := v.VerifyIdentity(bundle.Challenge, bundle.Identity, now)
	if err != nil {
		return PrincipalPolicy{}, err
	}
	verified, err := v.VerifyCommand(bundle.Challenge, bundle.Identity, bundle.Connect, command, expectedNetwork, expectedAddress, bundle.Challenge.SessionBinding, expectedNode, now)
	if err != nil {
		return PrincipalPolicy{}, err
	}
	if principal.ID != verified.ID {
		return PrincipalPolicy{}, ErrInvalidProof
	}
	return verified, nil
}
