package socksproof

import (
	"strings"
	"time"
)

// VerifyBundle reproduces client identity and destination authorization at the
// final owning node. It intentionally trusts only the verifier policy and signed
// bundle, not any intermediate verification result.
func (v *Verifier) VerifyBundle(bundle Bundle, expectedNetwork, expectedAddress, expectedNode string, now time.Time) (PrincipalPolicy, error) {
	if v == nil { return PrincipalPolicy{}, ErrUnauthorized }
	if strings.TrimSpace(bundle.Challenge.SelectedNode) != strings.TrimSpace(expectedNode) { return PrincipalPolicy{}, ErrInvalidProof }
	principal, err := v.VerifyIdentity(bundle.Challenge, bundle.Identity, now)
	if err != nil { return PrincipalPolicy{}, err }
	verified, err := v.VerifyConnect(bundle.Challenge, bundle.Identity, bundle.Connect, expectedNetwork, expectedAddress, bundle.Challenge.SessionBinding, expectedNode, now)
	if err != nil { return PrincipalPolicy{}, err }
	if principal.ID != verified.ID { return PrincipalPolicy{}, ErrInvalidProof }
	return verified, nil
}
