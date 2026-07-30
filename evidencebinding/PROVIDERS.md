# Cryptographic binding providers

The evidence core composes five distinct mechanisms. They solve different denial and tampering problems and must not be treated as interchangeable.

| Option | WeaverSSH implementation | What it detects | Boundary |
|---|---|---|---|
| Hash chaining | `PreviousSHA256`, sequence validation, and witnessed heads | Entry rewriting, removal, insertion, reordering, and replay inside the chain | A rewritten final entry requires an independently retained old head to detect it |
| Merkle trees | Domain-separated leaf/node hashes and inclusion proofs | Payload, metadata, sibling, direction, order, index, count, or root tampering | Inclusion proves membership in a batch, not that the batch is the latest one |
| Digital signatures | Ed25519, RSA-PSS/SHA-256, ECDSA P-256/SHA-256, and ECDSA P-384/SHA-384 | Statement mutation, key substitution, algorithm confusion, weak RSA keys, and wrong-curve ECDSA keys | Attribution is to possession of a configured trusted private key |
| Immutable database | `ImmuDBAnchor` using immugw verified safe set/get operations | Deletion or substitution of an anchored head when the verified database state is retained | WeaverSSH verifies the exact round trip; immudb supplies the immutable state and proof system |
| Permissioned ledger | `FabricAnchor` bridge requiring successful commit metadata and exact statement echo | Rejected commits, changed transaction payloads, provider/head replay, transaction or block substitution | The bridge must use Fabric Gateway and wait for successful commit status |

## Multi-algorithm digital signatures

`SignatureTrustPolicy` binds each key identifier to one exact algorithm and exact public-key encoding. The public key embedded in a receipt cannot authorize itself.

```mermaid
flowchart TD
    ST[Canonical evidence statement] --> DOMAIN[Statement domain separation]
    DOMAIN --> ALG{Configured algorithm}
    ALG -->|Ed25519| ED[Sign and verify Ed25519]
    ALG -->|RSA-PSS SHA-256| RSA[Hash SHA-256 then RSA-PSS]
    ALG -->|ECDSA P-256 SHA-256| P256[Hash SHA-256 then ECDSA ASN.1]
    ALG -->|ECDSA P-384 SHA-384| P384[Hash SHA-384 then ECDSA ASN.1]

    TRUST[Trusted key ID, algorithm, exact public key] --> MATCH{All three match receipt?}
    ED --> MATCH
    RSA --> MATCH
    P256 --> MATCH
    P384 --> MATCH
    MATCH -->|no| REJECT[Reject substitution or algorithm confusion]
    MATCH -->|yes| VERIFY[Verify signature]
```

RSA keys shorter than 2048 bits are rejected. P-256 and P-384 keys are rejected when used under the other curve's algorithm identifier.

## Immutable database anchoring with immudb

`ImmuDBAnchor` stores the canonical `AnchorStatement`, not a free-form status string. The key is deterministic for the stream and sequence, and the value is read back through immugw's verified safe-get endpoint before a receipt is returned.

```mermaid
sequenceDiagram
    participant W as WeaverSSH
    participant G as immugw
    participant D as immudb verified state

    W->>W: Canonicalize stream, sequence, statement SHA-256
    W->>W: Derive idempotency key and deterministic database key
    W->>G: POST /item/safe with base64 key and canonical value
    G->>D: Verified immutable write
    D-->>G: Write result
    G-->>W: Safe-set response
    W->>G: POST /item/safe/get for the same key
    G->>D: Verified read against retained state
    D-->>G: Stored canonical value and proof-backed result
    G-->>W: Base64 stored value
    W->>W: Require exact byte equality
    W-->>W: Emit provider-bound receipt
```

A successful HTTP write alone is insufficient. The adapter rejects the anchor unless the verified read returns exactly the canonical statement bytes.

## Permissioned-ledger anchoring with Hyperledger Fabric

`FabricAnchor` deliberately uses a narrow HTTP bridge contract so WeaverSSH does not import or embed a Fabric SDK. The bridge is responsible for using Fabric Gateway, submitting the configured chaincode transaction, and waiting for successful commit status.

```mermaid
sequenceDiagram
    participant W as WeaverSSH
    participant B as Fabric bridge
    participant G as Fabric Gateway
    participant L as Permissioned ledger

    W->>B: Submit channel, chaincode, function, idempotency key, exact AnchorStatement
    B->>G: Build and endorse transaction proposal
    G->>L: Submit transaction to ordering service
    L-->>G: Committed status, transaction ID, block number
    G-->>B: Successful committed transaction
    B-->>W: Exact statement echo, transaction ID, block number, successful=true
    W->>W: Reject failed commit or changed echo
    W->>B: Evaluate query for retained anchor
    B->>G: Evaluate configured read function
    G-->>B: Stored statement and commit metadata
    B-->>W: Exact retained statement
    W->>W: Compare provider, head, transaction ID, and block number
```

An endorsement result or submitted transaction without successful commit status is not accepted as an anchor.

## Composed verification path

```mermaid
flowchart LR
    PAYLOAD[Exact event bytes] --> LEAF[Leaf commitment]
    LEAF --> MERKLE[Merkle batch root]
    MERKLE --> CHAIN[Previous-hash statement chain]
    CHAIN --> SIGN[Trusted asymmetric signature]
    SIGN --> HEAD[Verified evidence head]
    HEAD --> IMMU[(immudb anchor)]
    HEAD --> FABRIC[(Fabric committed anchor)]
    IMMU --> QUORUM[N-of-M AnchorThresholdPolicy]
    FABRIC --> QUORUM
    QUORUM --> CHECK[Independent completeness and denial checks]
```

`AnchorThresholdPolicy` counts at most one valid receipt from each configured provider. Duplicate receipts, unknown providers, invalid receipts, and failed verification never increase quorum. This permits policies such as two valid anchors out of three independently operated providers.

Using multiple external providers gives independent failure domains, but it does not remove the need to protect signing keys, trust-policy configuration, immudb client state, Fabric identities, bridge credentials, or transport security.
