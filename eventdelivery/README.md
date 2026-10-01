# Event delivery core

An opt-in Go mechanism for scoped, configured event delivery. It does not select commands from events, evaluate business policy, schedule cron jobs, send webhooks, or automatically connect itself to existing replay/command runners.

The host resolves a `Route` and an immutable event/schedule `Occurrence`, supplies the four adapters to `New`, and calls `Attempt` once per scheduled attempt. The package:

- freezes the configured kind, target, authority reference, generation and occurrence parameters;
- rejects scope/route/generation mismatches and absent adapters;
- resolves current configuration and independently authorizes every attempted effect;
- pins the first accepted authority generation and rejects a changed generation on retry;
- preserves one delivery key across retries, stops after success, and enforces a configured attempt limit;
- requires evidence acknowledgement before the effect and after its observed outcome;
- retains ambiguous effects or missing outcome evidence as `outcome-unknown`, requiring host/operator reconciliation.

`Authorize` is a required host-owned adapter. Use the host's canonical authority/policy implementation; event fields, provider replies, a configured authority name, and a matching scope are not grants. `Execute` must enforce grant fencing at the actual effect boundary. Resolver/authorizer observations in this package do not establish atomic revocation across another process or remote receiver.

## Delivery identity and input bounds

`ed1_` plus the lowercase SHA-256 digest of the compact JSON string tuple:

```text
["eventdelivery/v1", scope, routeID, decimalRouteGeneration, kind, targetID, authorityReference, occurrenceID]
```

Identifiers use ASCII letters, digits and `-_.:/~`, with a 256-byte maximum. Parameters are bounded to 64 entries and 4096 bytes per value. MaxAttempts must be 1–1024; this is an engineering resource limit, not a policy/legal time limit. Retry number, parameter values and provider replies do not change the key. Host intake must authenticate scope and persist immutable occurrence identity/content; this package does not validate producer signatures or detect a forged reuse of an occurrence ID.

## Outcomes and evidence

Only explicit `RetryableFailure` returns the delivery to pending. `Success` stops retry; permanent failure and the attempt limit produce dead-letter state. An execution error or unknown result produces `outcome-unknown` rather than asserting that no effect happened. This is a conservative default for automatic retries, not a change to an existing replay API. A host may deliberately replay using the same identity under its normal authority/approval rules.

The evidence callback receives causal IDs, authority generation, candidate/actual attempt index, stage, state, typed outcome and a fixed reason code. Event payloads, raw provider errors and webhook secrets are not fields of this evidence structure. `started` acknowledges permission to attempt before the effect; it does not prove that the effect happened. If cancellation intervenes, a refused record follows and the actual effect count stays unchanged. A rejected gate may record the count of previously executed attempts without executing another effect. Evidence durability and access control are the host adapter's responsibility.

Missing pre-effect evidence prevents execution. Missing post-effect evidence keeps the observed result in memory but cannot report an accepted success. An adapter panic propagates to its caller and fences this instance as unknown; the prior started record must be reconciled by the host. No fabricated outcome record is written from a panic handler.

## Idempotency, concurrency and recovery limits

This package guarantees a stable delivery key, not global idempotency. Separate Delivery instances, restarts, explicit transfer replay, scripts and external receivers may repeat successful actions. External systems can use the key to deduplicate or perform compensation. Successful replay is not silently converted into a no-op.

Concurrent calls are fenced only within one in-memory instance. Production integration still needs a durable occurrence/intent store, claims/CAS and fencing, persisted attempt/authority state, dead-letter handling and unknown-outcome recovery. Callbacks run without the Delivery mutex held and must honor the caller's bounded context; the host supplies backoff/scheduling. Existing automation stays unchanged until an adapter is deliberately wired and accepted.

## Verification

This package depends only on the Go standard library. A focused command, run from this directory, is:

```sh
GOWORK=off GO111MODULE=off go test -race -count=1 -timeout=60s -v .
```

Use the repository's operational runner where supplied. The tests cover configured-action isolation, independent authorization, disabled/stale route retries, authority revocation/rotation, stable scoped keys, terminal outcomes, attempt limits, evidence failure, cancellation, concurrent calls, adapter interruption, and explicit replay semantics. CI runs these tests against this package; a configured workflow or an unrun test is not a passing receipt.

The proposed EventRouteDispatch, RetryAuthority, WebhookDelivery and ScheduleTrigger formal refinements have not been imported or checked by this package. Exact models, 22 negative-control configurations, Lean/OCaml sources and cross-tool registry are needed before any formal coverage claim.
