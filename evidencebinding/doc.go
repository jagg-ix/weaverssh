// Package evidencebinding provides cryptographic commitments and verification
// for independently retainable WeaverSSH evidence receipts.
//
// The package binds exact payload bytes to domain-separated Merkle leaves,
// signs append-only stream checkpoints with trusted Ed25519 keys, verifies
// statement-chain continuity, and detects conflicting statements observed at
// the same stream position.
//
// A valid signature establishes that the holder of a configured trusted key
// signed the checkpoint. It does not by itself prove that a presented local
// history is complete. Detecting deletion of a valid suffix requires an
// independently retained witnessed head. The algorithms, threat model, and
// verification boundary are diagrammed in README.md.
package evidencebinding
