package socksproof

// Bundle contains every signed object required to reproduce SOCKS5 CONNECT
// authorization at the final node. Intermediates must forward it unchanged.
type Bundle struct {
	Challenge Challenge      `json:"challenge"`
	Identity  SignedIdentity `json:"identity"`
	Connect   SignedConnect  `json:"connect"`
}
