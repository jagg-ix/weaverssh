# Stateful terminal sessions over the WeaverSSH tunnel

Interactive PTYs are not files. WeaverSSH therefore uses the typed Exec service
as the primary non-interactive API, keeps `containerstream.ProcessFS` as a
composable VFS/9P facade over the same process manager, and carries interactive
terminals on a separate `terminal` mux service. All three views use the same
provider abstraction and authenticated SSH-derived node routing; only the
terminal manager owns detach, reattach, replay, and PTY attachment generations.

The terminal service combines two established ideas:

- a SOCKS-style negotiation phase selects a target and mode before any bytes
  flow; and
- a tmux-style agent owns the remote PTY, so the local client remains a raw
  renderer and a tunnel disconnect need not terminate the process.

## Service and trust boundary

`sessionmux.ServiceTerminal` is wire ID 7. A signed node context must explicitly
contain `terminal.session`; VFS, SOCKS, or compute capabilities do not imply it.
The service is routable through the existing node registry and final-node
allowlist.

Mux OPEN metadata uses `weaverssh.terminal-open.v1` and contains only target and
broker-bound provenance. The broker binds the authenticated source node,
session binding, and topology-chain digest. Commands and resume tokens are sent
only after the target stream has been authorized and acknowledged. A terminal
OPEN payload cannot claim an identity.

The final-node `terminalsession.PolicyAuthorizer` is mandatory and default-deny. It
maps a policy action plus bounded arguments to an absolute `ProcessSpec`; no
shell command string is accepted. It runs again for every reattach. A deployment
can map the authenticated source binding to an SSO principal with
`Server.ResolvePrincipal`. The same authorizer implements the provider-neutral
`ProcessAuthorizer` used by routed non-interactive Exec and ProcessFS, so target,
argv, environment, timeout, and stdin policy cannot drift between facades.

## Framed cut-through protocol

Each terminal stream starts with one bounded `OPEN` frame. On success, the
agent returns `READY`; subsequent data remains a raw byte flow wrapped only so
that terminal control cannot collide with application bytes.

| Frame | Direction | Purpose |
|---|---|---|
| `OPEN` | client to agent | connect or reattach negotiation |
| `READY` / `ERROR` | agent to client | negotiation result |
| `INPUT` | client to agent | raw terminal input |
| `OUTPUT` | agent to client | PTY output plus monotonic sequence |
| `RESIZE` | client to agent | four-byte rows/columns OOB control |
| `DETACH` | client to agent | preserve PTY and start TTL |
| `TERMINATE` | client to agent | close PTY and free resources |
| `EXIT` | agent to client | process exit or explicit termination acknowledgement |
| `PING` / `PONG` | either direction | stream liveness |

The fixed 20-byte `WVT1` header contains type, flags, a 64-bit output sequence,
and a bounded payload length. Sequence numbers make replay idempotent: a client
reattaches with `after_sequence`, discards any duplicate sequence, and receives
`TRUNCATED` if its requested history has fallen out of the bounded tail buffer.

The initial `READY` is the only message that carries the random resume token.
The manager stores its SHA-256 digest, and reattach requires both the token and
the same authenticated principal/source/binding/chain fingerprint.

## Agent policy and client workflow

The service is disabled unless the final node is started with an explicit
default-deny policy. [`terminal-policy.json`](../examples/terminal-policy.json)
is a deliberately narrow example; deployments must replace its identities and
targets. The machine-readable contract is
[`terminal-policy.v1.schema.json`](../../api/schema/terminal-policy.v1.schema.json).
An action maps to one clean absolute POSIX executable plus fixed arguments. Client
arguments are bounded, client-supplied environment variables are rejected, and
credential-like environment names are rejected even in policy. Target,
provider, orchestration options, principal, and authenticated source must all
match the action.

The command-line service treats the authenticated source-node ID as its
principal, so the example repeats `laptop` in `principals` and `sources`.
Embedded deployments can set `TerminalServiceConfig.ResolvePrincipal` to map
the broker-bound provenance to an SSO principal; the OPEN payload cannot supply
or override that value.

Enable the final-node service with `wv attach` or `wv session-host`:

```bash
wv attach \
  --node-context node-context.json \
  --public-key-file authority.pub \
  --terminal-policy terminal-policy.json \
  --terminal-recording terminal-recording.ndjson
```

The signed node context must independently grant `terminal.session`. A policy
whose action requires recording fails closed unless a recording sink was
configured and remains writable.

The local CLI performs negotiation over the active same-user session broker;
it does not open a terminal listener or static forwarding port:

```bash
wv terminal connect \
  --provider kubernetes --namespace staging --container api \
  worker-a api-0 debug-shell

wv terminal connect \
  --provider nomad --namespace staging --task api \
  worker-a 5456bd7a-9fc0-c0dd-6131-cbee77f57577 debug-shell

# Ctrl-] detaches without killing the provider PTY.
wv terminal inspect --json SESSION_ID
wv terminal reattach SESSION_ID
wv terminal terminate SESSION_ID
```

The initial connection persists the resume token and replay cursor in an
owner-only state file below `$XDG_STATE_HOME/weaverssh/terminals` (or the
platform state-directory fallback). `inspect`, including `--json`, never emits
the token. Replayed output is sequence-deduplicated and the cursor is saved
after each rendered frame. `terminate` drains pending replay concurrently,
waits for the agent's `EXIT` acknowledgement, and only then erases the local
resume token.

## Agent-owned lifecycle

| State | Allowed next states |
|---|---|
| `PROVISIONING` | `ACTIVE`, `TERMINATED` |
| `ACTIVE` | `DETACHING`, `RECOVERING`, `TERMINATED` |
| `DETACHING` | `DETACHED`, `TERMINATED` |
| `DETACHED` | `RECOVERING`, `TERMINATED` |
| `RECOVERING` | `ACTIVE`, `DETACHED`, `TERMINATED` |
| `TERMINATED` | none |

`ACTIVE -> RECOVERING` is intentional. It is the ghost-connection rule: after
the same owner reauthenticates, the manager closes the old attachment and
increments a generation lease. Every input, resize, detach, and terminate
operation must present the current generation, so a late handler from the old
tunnel cannot affect the new session.

Each session has one mutation lock order: lifecycle I/O lock, attachment-send
lock, then state mutex. Output uses only attachment-send then state mutex and
never takes them in reverse. A recovery holds the send lock while it sends
`READY` and the ring snapshot; output generated concurrently is retained and is
sent only after the session becomes active, preserving sequence order.

TTL expiry and reattach take the same lifecycle lock. If expiry first marks the
session `TERMINATED`, reattach cannot resurrect it. If reattach first enters
`RECOVERING`, it invalidates and stops the detached timer; the stale callback
observes a different state/epoch and exits.

The executable model in
[`tools/verification/tla/terminal_session`](../../tools/verification/tla/terminal_session/)
checks final termination, attachment-generation coherence, TTL scope, and stale
writer exclusion across all bounded interleavings. Race-enabled Go tests cover
the corresponding implementation.

## PTY ownership and adapters

`terminalsession.ContainerSpawner` requests a TTY through the existing
orchestration provider router and rejects any provider that cannot truthfully
advertise TTY, stdin, stdout, resize, and termination of the exact remote exec.
This is deliberately stricter than ProcessFS. The built-in Podman Libpod 4.8+
adapter meets that contract and force-removes the exact exec ID on close or TTL
expiry. Kubernetes/Rancher WebSocket/SPDY and Nomad WebSocket adapters provide
TTY plus resize for direct ProcessFS use, but their APIs do not portably prove
exact-exec termination when an attachment closes, so they fail closed here.
The CLI fallbacks, CRI CLI, and Docker Engine API also fail closed for this
service.

The process is created with the manager lifetime rather than the attachment
lifetime. A tunnel loss therefore detaches the client while the agent continues
reading the provider PTY into a bounded in-memory ring. An agent or provider
connection failure still ends the session; this is detach resilience, not
cross-agent process migration.

The manager is tmux-like by architecture, not by subprocess dependency. tmux
was not made the default because its private Unix socket and terminal server
would duplicate WeaverSSH's ownership state, exclude native Windows agents,
and cannot make a wrapped container CLI's remote termination semantics
truthful. Trusted embedders can inject a `TerminalServiceConfig.Spawner` plugin
for tmux, abduco, or another owner while leaving authorization, authenticated
reattach, replay, TTL, and recording in WeaverSSH. Such a plugin must guarantee
that teardown stops the policy-authorized remote process, not merely a local
container CLI wrapper. No external backend is enabled by environment discovery.

## Recording

Recording is policy-controlled as `off`, `best-effort`, or `required`.
`HashChainRecorder` writes replayable NDJSON with exact base64 output bytes,
sequence, timestamp, previous digest, and entry digest. `required` fails closed
if its sink fails. Because terminal output can contain secrets, raw recording is
never implicit.

When an existing recording file is reopened, WeaverSSH verifies the complete
digest chain before appending and refuses to resume modified entries or a
malformed partial tail. Detecting removal of a complete valid suffix requires
anchoring the latest digest in the independent evidence journal or a SIEM.
Recording and reconnect-state files are forced to owner-only mode and symlink
paths are rejected.

`EvidenceRecorder` and `JournalObserver` integrate with the existing signed,
anchored agent evidence journal. They record lifecycle transitions and output
digests/sizes, not resume tokens or raw terminal bytes. Multiple sinks can be
combined for SIEM playback plus independent integrity evidence.

## Architectural references

- The [tmux client/server description](https://github.com/tmux/tmux/wiki/Getting-Started#the-tmux-server-and-clients)
  documents a background server that owns program state and supports detached
  clients.
- Lamport's [high-level view of TLA+](https://lamport.azurewebsites.net/tla/high-level-view.html)
  describes executions as sequences of states and steps, matching the session
  model in this repository.
- POSIX specifies that a competing thread blocks while a mutex is owned in
  [`pthread_mutex_lock`](https://pubs.opengroup.org/onlinepubs/9799919799/functions/pthread_mutex_lock.html).
- Kubernetes' [CRI streaming explanation](https://kubernetes.io/blog/2024/05/01/cri-streaming-explained/)
  documents `Exec` and `Attach` as preparation of interactive streaming
  endpoints; the adapter boundary remains neutral to the concrete transport.
