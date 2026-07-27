package authproof

import (
	"errors"
	"fmt"
	"strings"
)

const (
	SecurityLevelCompat     = "compat"
	SecurityLevelSameUID    = "same_uid"
	SecurityLevelX11Cookie  = "x11_cookie"
	SecurityLevelAgentProof = "agent_proof"
	SecurityLevelStrict     = "strict"
)

const (
	RequirementSameUID           = "same_uid"
	RequirementX11Cookie         = "x11_cookie"
	RequirementAgentKeyProof     = "agent_key_proof"
	RequirementNoAdditionalCheck = "no_additional_check"
)

var (
	ErrInvalidSecurityLevel  = errors.New("invalid security level")
	ErrInsufficientAuthority = errors.New("insufficient authority evidence")
	ErrWrongSecurityLevel    = errors.New("wrong security level")
)

// AuthorityEvidence is the local admission evidence available before a
// component accepts local bytes or promotes an X11/WebSocket session to relay.
// AgentSocketPresent is intentionally not sufficient for high-security levels;
// high levels require AgentKeyProofVerified, meaning a key-backed proof was
// actually verified and bound to the current X11 cookie/session context.
type AuthorityEvidence struct {
	SameUID               bool
	X11CookieMatched      bool
	AgentSocketPresent    bool
	AgentKeyProofVerified bool
	PrincipalUID          string
	ComponentUID          string
}

type AuthorityDecision struct {
	Level    string   `json:"level"`
	Allowed  bool     `json:"allowed"`
	Required []string `json:"required"`
	Missing  []string `json:"missing"`
	Notes    []string `json:"notes"`
}

func NormalizeSecurityLevel(level string) string {
	switch strings.ToLower(strings.TrimSpace(strings.ReplaceAll(level, "-", "_"))) {
	case "", "auto", SecurityLevelCompat:
		return SecurityLevelCompat
	case "sameuid", "same_uid", "uid":
		return SecurityLevelSameUID
	case "cookie", "x11", "x11_cookie", "mit_cookie", "mit_magic_cookie":
		return SecurityLevelX11Cookie
	case "agent", "agent_proof", "ssh_agent", "ssh_agent_proof", "key_proof", "private_key":
		return SecurityLevelAgentProof
	case SecurityLevelStrict:
		return SecurityLevelStrict
	default:
		return strings.ToLower(strings.TrimSpace(level))
	}
}

func KnownSecurityLevel(level string) bool {
	switch NormalizeSecurityLevel(level) {
	case SecurityLevelCompat, SecurityLevelSameUID, SecurityLevelX11Cookie, SecurityLevelAgentProof, SecurityLevelStrict:
		return true
	default:
		return false
	}
}

func ValidateSecurityLevel(level string) error {
	if !KnownSecurityLevel(level) {
		return fmt.Errorf("%w: %q", ErrInvalidSecurityLevel, level)
	}
	return nil
}

func SecurityLevelRequiresSignedProof(level string) bool {
	switch NormalizeSecurityLevel(level) {
	case SecurityLevelAgentProof, SecurityLevelStrict:
		return true
	default:
		return false
	}
}

func SecurityLevelRequirements(level string) []string {
	switch NormalizeSecurityLevel(level) {
	case SecurityLevelCompat:
		return []string{RequirementNoAdditionalCheck}
	case SecurityLevelSameUID:
		return []string{RequirementSameUID}
	case SecurityLevelX11Cookie:
		return []string{RequirementSameUID, RequirementX11Cookie}
	case SecurityLevelAgentProof:
		return []string{RequirementX11Cookie, RequirementAgentKeyProof}
	case SecurityLevelStrict:
		return []string{RequirementSameUID, RequirementX11Cookie, RequirementAgentKeyProof}
	default:
		return nil
	}
}

func EvaluateAuthority(level string, evidence AuthorityEvidence) (AuthorityDecision, error) {
	normalized := NormalizeSecurityLevel(level)
	if err := ValidateSecurityLevel(normalized); err != nil {
		return AuthorityDecision{Level: normalized, Allowed: false}, err
	}
	decision := AuthorityDecision{
		Level:    normalized,
		Required: SecurityLevelRequirements(normalized),
		Notes:    []string{},
	}
	missing := make([]string, 0, len(decision.Required))
	for _, requirement := range decision.Required {
		switch requirement {
		case RequirementNoAdditionalCheck:
		case RequirementSameUID:
			if !evidence.SameUID {
				missing = append(missing, requirement)
			}
		case RequirementX11Cookie:
			if !evidence.X11CookieMatched {
				missing = append(missing, requirement)
			}
		case RequirementAgentKeyProof:
			if !evidence.AgentKeyProofVerified {
				missing = append(missing, requirement)
			}
		}
	}
	if evidence.AgentSocketPresent && !evidence.AgentKeyProofVerified {
		decision.Notes = append(decision.Notes, "agent_socket_present_without_verified_key_proof")
	}
	if evidence.PrincipalUID != "" && evidence.ComponentUID != "" && evidence.PrincipalUID == evidence.ComponentUID && !evidence.SameUID {
		decision.Notes = append(decision.Notes, "uid_fields_match_but_same_uid_flag_not_set")
	}
	decision.Missing = missing
	decision.Allowed = len(missing) == 0
	if !decision.Allowed {
		return decision, ErrInsufficientAuthority
	}
	return decision, nil
}
