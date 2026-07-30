// Package evidencebinding provides cryptographic commitments and verification
// for independently retainable WeaverSSH evidence receipts.
//
// The package binds exact payload bytes to domain-separated Merkle leaves,
// signs append-only stream checkpoints with trusted Ed25519, RSA-PSS, or ECDSA
// keys, verifies statement-chain continuity, and detects conflicting statements
// observed at the same stream position.
//
// Verified heads can be anchored through immugw safe set/get operations or a
// narrow Hyperledger Fabric bridge that must return successful commit status,
// transaction identity, block identity, and an exact statement echo.
//
// A valid signature establishes that the holder of a configured trusted key
// signed the checkpoint. It does not by itself prove that a presented local
// history is complete. Detecting deletion or rewriting of a valid suffix
// requires an independently retained witnessed head or an independently
// retained external anchor. The core algorithms are diagrammed in README.md;
// provider composition and trust boundaries are diagrammed in PROVIDERS.md.
package evidencebinding
