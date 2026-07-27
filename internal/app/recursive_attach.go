package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"weaverssh/authproof"
	"weaverssh/hopproof"
)

// VerifiedRecursiveHop is the authenticated path that terminates at the local
// attached node.
type VerifiedRecursiveHop struct {
	Chain        hopproof.Chain
	PreviousNode string
	Depth        int
}

// VerifyIncomingRecursiveHop validates the complete WVHOP chain and confirms
// that WVORIGIN names its immediate predecessor. When required is false, an
// absent WVHOP preserves the non-recursive single-hop workflow.
func VerifyIncomingRecursiveHop(
	ctx context.Context,
	nodeContext authproof.NodeContext,
	encoded string,
	wvOrigin string,
	allowedSignersFile string,
	sshKeygenBinary string,
	required bool,
	now time.Time,
) (VerifiedRecursiveHop, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		if required {
			return VerifiedRecursiveHop{}, fmt.Errorf("recursive attach requires %s", EnvWVHop)
		}
		return VerifiedRecursiveHop{}, nil
	}
	if strings.TrimSpace(allowedSignersFile) == "" {
		return VerifiedRecursiveHop{}, errors.New("recursive attach requires --hop-allowed-signers")
	}
	return verifyIncomingRecursiveHop(
		ctx,
		nodeContext,
		encoded,
		wvOrigin,
		hopproof.SSHKeygenVerifier{Binary: sshKeygenBinary, AllowedSignersFile: allowedSignersFile},
		now,
	)
}

func verifyIncomingRecursiveHop(
	ctx context.Context,
	nodeContext authproof.NodeContext,
	encoded string,
	wvOrigin string,
	verifier hopproof.Verifier,
	now time.Time,
) (VerifiedRecursiveHop, error) {
	chain, err := hopproof.Decode(strings.TrimSpace(encoded))
	if err != nil {
		return VerifiedRecursiveHop{}, err
	}
	if err := hopproof.Verify(ctx, nodeContext, chain, verifier, hopproof.VerifyOptions{
		Now:         now,
		MaxTTL:      10 * time.Minute,
		ReplayCache: authproof.NewNonceCache(),
	}); err != nil {
		return VerifiedRecursiveHop{}, err
	}
	previous, err := hopproof.ImmediatePrevious(chain)
	if err != nil {
		return VerifiedRecursiveHop{}, err
	}
	if strings.TrimSpace(wvOrigin) != previous {
		return VerifiedRecursiveHop{}, fmt.Errorf("%s=%q does not match signed hop predecessor %q", EnvWVOrigin, wvOrigin, previous)
	}
	return VerifiedRecursiveHop{Chain: chain, PreviousNode: previous, Depth: len(chain.Hops)}, nil
}
