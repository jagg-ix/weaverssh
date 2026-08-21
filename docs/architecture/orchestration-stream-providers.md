# Orchestration-neutral container streams

WeaverSSH reserves a provider-neutral VFS namespace for reading a continuous
byte stream from an already-running containerized workload:

```text
vfs://container/ENDPOINT/TARGET/ABSOLUTE/PATH
```

For example:

```bash
wv cat 'vfs://container/rancher-node/pod-abc/data.bin?namespace=jobs&container=worker'
wv cat 'vfs://container/local/api-1/var/log/app.log?provider=podman'
```

`ENDPOINT` is a logical WeaverSSH/orchestration node, `TARGET` is an opaque pod,
container, or allocation ID, and the remainder is the absolute path inside the
workload. The URI does not encode Kubernetes, Docker, Podman, or Nomad into the
scheme. Provider-specific qualifiers are bounded query options.

## Provider contract

The public `containerstream.Provider` interface is intentionally small:

```go
type Provider interface {
    Name() string
    OpenContainerStream(context.Context, Request) (io.ReadCloser, error)
}
```

The VFS caller receives only an `io.ReadCloser`. It does not know whether the
provider reached the workload through a CLI, a local socket, CRI gRPC, or a
scheduler API. Applications can register or replace providers without changing
the URI parser or router. Plugins can implement `DiscoverableProvider` to add
their own bounded availability evidence to automatic selection.

## Shared non-interactive process manager

Execution is an optional extension of the provider contract:

```go
type ExecutionProvider interface {
    Provider
    StartContainerProcess(context.Context, Request, ProcessSpec) (Process, error)
}
```

`containerstream.ProcessManager` is the only non-interactive process lifecycle
owner. It applies broker-derived identity, final-node action authorization,
provider selection and pinning, session and stdin limits, single-consumer
stream rules, wait state, and generation-safe teardown. Two adapters use it:

- the typed, routed `containerexec` protocol is the primary remote execution
  API; and
- `ProcessFS` is a composable file-shaped facade for VFS/9P clients.

They do not maintain separate process registries or invoke providers directly.
Interactive terminal ownership, detach/reattach, replay, and out-of-band resize
use the separate [stateful terminal service](terminal-session-hybrid.md).

`Process` exposes standard stream handles, `Wait`, `Close`, and capability-
checked `Signal` and `Resize` methods. A read-only provider remains valid; a
router returns `ErrExecutionUnsupported` if it is asked to execute. This keeps
file streaming and active process mechanics independently pluggable.
`ProcessCapabilities.Terminate` separately declares that `Close` stops the
exact remote exec process rather than only closing a client attachment or
local wrapper.

### Typed streaming Exec protocol

`sessionmux.ServiceExec` carries `weaverssh.container-exec.v1` on the same
authenticated tunnel as every other service. The local broker binds source
node, session binding, and chain digest into
`weaverssh.container-exec-open.v1` metadata before routing. The final node
rejects a target URI whose endpoint does not equal the routed node.

The protocol uses bounded typed frames: `START`, `READY`, `STDIN`,
`CLOSE_STDIN`, `SIGNAL`, `STDOUT`, `STDERR`, `EXIT`, and `ERROR`. It is
non-TTY and non-detachable by design. stdout and stderr remain distinct and
stream under mux backpressure; they are not accumulated into an RPC response.
The signed node context needs the narrow `compute.exec` capability; legacy
`compute.mapreduce` contexts remain compatible.

Enable it with the same action-policy format used by terminals:

```bash
wv attach \
  --node-context node-context.json \
  --public-key-file authority.pub \
  --container-exec-policy process-policy.json

wv exec \
  --container 'vfs://container/worker-a/api-0/proc/exec?provider=kubernetes&namespace=staging&container=api' \
  --input request.bin \
  worker-a inspect-build artifact-42
```

`ACTION` resolves to a fixed absolute argv at the final node. The request
contains neither an executable nor a shell string and cannot supply identity or
environment values. Without `--container`, `wv exec` retains its existing
bounded host-action protocol for compatibility.

[`process-policy.json`](../examples/process-policy.json) is a restricted
example. The wire-compatible policy schema is shared with the terminal service
so a deployment can intentionally authorize the same action in both modes.

### ProcessFS facade

`containerstream.ProcessFS` presents each active process as a synthetic
directory:

Base URI: `vfs://container/ENDPOINT/TARGET/.wv/processes/SESSION/`

| File | Access | Semantics |
|---|---|---|
| `ctl` | write-only | transactional control messages |
| `stdin` | write-only | live and single-consumer |
| `stdout` | read-only | live and single-consumer |
| `stderr` | read-only | live and single-consumer |
| `status` | read-only | JSON lifecycle snapshot |

Creating the directory does not execute anything. Closing a `ctl` writer
commits exactly one bounded JSON message. The initial operation names a policy
action rather than an executable:

```json
{
  "protocol": "weaverssh.procctl.v1",
  "op": "start",
  "action": "inspect-build",
  "args": ["artifact-42"],
  "environment": {"LANG": "C"},
  "tty": false
}
```

The required shared `ProcessAuthorizer` resolves that action to an absolute argv and
applies authenticated source, target, argument, environment, timeout,
session, and stdin limits. Neither `ProcessManager` nor the compatibility
`ProcessFS` constructor can be constructed without an authorizer. ProcessFS
rejects unknown JSON fields, repeated starts, arbitrary command
fields, shell strings, credential-like environment names, oversized control
messages, invalid signals, and access in the wrong direction.

Later control messages use the same protocol:

```json
{"protocol":"weaverssh.procctl.v1","op":"signal","signal":"SIGINT"}
{"protocol":"weaverssh.procctl.v1","op":"resize","rows":42,"cols":120}
{"protocol":"weaverssh.procctl.v1","op":"close-stdin"}
{"protocol":"weaverssh.procctl.v1","op":"close"}
```

The bounded signal vocabulary is `SIGHUP`, `SIGINT`, `SIGQUIT`, `SIGTERM`,
`SIGKILL`, and `SIGWINCH`; resize carries rows and columns separately.

`status` moves through `created`, `starting`, `running`, and `exited`, with
`failed` for launch failures and `closed` for explicit teardown. It reports the
selected provider, transport capabilities, timestamps, stdin byte count, and
exit code without echoing argv or environment values.

Payloads are never staged to disk. The process object owns the three live
streams; session metadata alone is retained in memory. Stream backpressure is
therefore end-to-end. Each stream is single-consumer so multiple readers cannot
silently split output.

### Routed 9P attach

ProcessFS is carried as the typed `weaverssh.processfs-open.v1` subprotocol on
the existing `sessionmux.ServiceFS` channel. It does not create a TCP listener,
request static forwarding, or add a second SSH transport. The first same-user
broker binds source node, session binding, and topology-chain digest; forwarding
preserves that provenance, and the final node rejects a container URI whose
endpoint differs from the routed node.

Every accepted attach creates one synthetic session and presents that session
directory as the 9P root. The root stat is named with the random session ID and
contains only `ctl`, `stdin`, `stdout`, `stderr`, and `status`. This per-attach
shape avoids merging active process handles into the OS-backed export and keeps
ordinary `NODE:/path` behavior unchanged. Closing the transport removes the
session and closes the provider process; detachable PTYs remain the job of the
terminal service.

The synthetic server supports concurrent tagged 9P requests, so a blocking
`stdout` read does not prevent a separate `stdin` write or control clunk on the
same transport. Stream offsets must be sequential, control is committed only
by an explicit `Tclunk`, and an incomplete `ctl` payload is discarded if the
transport disappears. Create, remove, traversal, and wrong-direction opens are
rejected.

The signed node context must grant both filesystem routing (`vfs.mesh` or
`file.backhaul`) and container execution (`compute.exec`, with legacy
`compute.mapreduce` compatibility). Consequently, enabling container Exec with
only `compute.exec` does not silently expose ProcessFS. The final-node action
policy remains independently default-deny.

### Capability truthfulness

The common denominator is non-TTY standard I/O. Portable CLI fallbacks run
argv-only interactive commands and advertise stdin/stdout/stderr, but not TTY,
remote signals, resize, or exact-exec termination. Killing a local `kubectl`,
`docker`, or `nomad` wrapper is not represented as signaling or terminating its
remote child.

| Transport | stdin/out/err | TTY | remote signals | resize | exact exec termination |
|---|---:|---:|---:|---:|---:|
| Built-in CLI fallback | yes | no | no | no | no |
| Built-in Docker Engine API | yes | no | no | no | no |
| Built-in Podman Libpod API | yes (stderr is combined for TTY) | yes | no | yes | yes, Libpod 4.8+ TTY |
| Built-in Kubernetes/Rancher API | yes (stderr is combined for TTY) | yes | no | yes | no |
| Custom provider plugin | provider-declared | provider-declared | provider-declared | provider-declared | provider-declared |
| Built-in Nomad allocation-exec API | yes (stderr is combined for TTY) | yes | no | yes | no |

An API/socket plugin must declare only the operations it can translate to the
remote process. Unsupported control writes return `ErrControlUnsupported`
instead of degrading to a local approximation.

### Provider pinning

Discovery may be locked or per-request, but a process is always pinned after
`start`: stdin, output, control, wait, and teardown operate on the returned
process object. No session can switch runtime adapters while it is active.

### Agent integration boundary

The configured container Exec service constructs one manager and exposes a
`ProcessFS` facade over that exact manager. `containerexec.Server.ProcessFS`
passes the facade to the final-node typed 9P dispatcher, while both Exec frames
and synthetic file operations still resolve to the same manager-owned process
handles.

The ordinary empty-metadata P9 service continues to serve only its configured
OS directory. ProcessFS is selected before that path only when strict typed
metadata validates, and is served as a separate per-process root rather than a
reserved directory injected into `NODE:/`. The existing
`wv cat vfs://container/...` command remains a read-only, host-local adapter
diagnostic; streaming `wv exec --container` is the primary routed CLI. Embedded
clients can open the typed broker stream and attach `internal/p9client` without
staging data or creating another process implementation.

Built-in adapters use argv-only CLI execution—never a shell—and stream stdout
without buffering the entire file:

| Provider | Safe-path command |
|---|---|
| Kubernetes | `kubectl exec POD [-c CONTAINER] -- cat -- PATH` |
| Rancher/K3s | `k3s kubectl exec POD [-c CONTAINER] -- cat -- PATH` |
| CRI | `crictl exec CONTAINER cat -- PATH` |
| Docker | `docker exec CONTAINER cat -- PATH` |
| Podman | `podman exec CONTAINER cat -- PATH` |
| Nomad | `nomad alloc exec -i=false -t=false ALLOCATION cat -- PATH` |

Kubernetes and Rancher/K3s additionally use the official
`client-go/tools/remotecommand` implementation. The native adapter loads the
selected kubeconfig context or in-cluster identity, attempts the current
WebSocket exec protocol, and falls back to SPDY only for an HTTP upgrade or
HTTPS-proxy failure. Other errors cannot start a second command. Argv remains a
repeated API query parameter rather than a shell string. TTY sessions carry a
bounded last-value resize queue; Kubernetes exec exposes no portable
per-process signal or exact-exec termination operation, so `Signals` and
`Terminate` remain false. Direct ProcessFS clients may still use the declared
TTY and resize operations, but the detachable terminal service rejects this
adapter.

Nomad additionally uses its documented allocation-exec WebSocket protocol.
The native adapter sends argv as a JSON array, stdin and resize as typed JSON
frames, keeps stdout/stderr separate outside TTY mode, consumes heartbeats, and
returns the explicit exit code. `NOMAD_TOKEN` is sent in the first
`ws_handshake` frame rather than the URL. `NOMAD_ADDR`, `NOMAD_CACERT`,
`NOMAD_CLIENT_CERT`, `NOMAD_CLIENT_KEY`, `NOMAD_TLS_SERVER_NAME`, and
`NOMAD_SKIP_VERIFY` configure the agent-side client. The native endpoint
requires `?task=NAME`; when it is absent before execution, the adapter safely
uses the CLI path, which can resolve a default task. Nomad's signal endpoint is
task/allocation-scoped rather than exec-process-scoped and is therefore not
advertised. Closing the allocation-exec WebSocket also cannot guarantee exact
process termination across task drivers, so `Terminate` remains false and the
detachable terminal service rejects this adapter.

Docker and Podman include a local socket API fast path. It accepts only local
Unix sockets, negotiates the daemon API version, creates an exec instance,
upgrades one HTTP connection to a raw duplex stream, and inspects the final
exit code. Non-TTY output is demultiplexed into stdout and stderr. Docker uses
the compatible API through `DOCKER_HOST=unix://...` or `/var/run/docker.sock`;
Podman separately negotiates and uses the native Libpod API through
`CONTAINER_HOST=unix://...`, the rootless
`$XDG_RUNTIME_DIR/podman/podman.sock`, or `/run/podman/podman.sock`. TCP engine
URLs are deliberately left to the CLI adapter and its configured context.

The Docker-compatible transport is intentionally non-TTY and does not
advertise signals or resize: Docker exposes no portable per-exec kill or signal
operation. Closing a Docker attachment releases WeaverSSH's streams but cannot
promise to terminate an arbitrary still-running remote exec, so policies
should keep those actions intrinsically bounded.

Podman's Libpod extension supplies the missing lifecycle operations. For TTY
exec, WeaverSSH consumes the raw combined output stream, sends dimensions to
the Libpod per-exec resize endpoint, and issues forced removal for that exact
exec ID on close or TTL expiry. Forced exec removal was introduced in Libpod
API 4.8.0, so older services retain compatible non-TTY streaming but reject a
detachable PTY before creating it. This makes supported Podman releases
eligible for the stateful terminal service without bundling tmux or invoking
the Podman CLI. Libpod still has no per-exec signal endpoint, so `Signals`
remains false. A custom provider must implement equally faithful remote
control before declaring additional capabilities.

`NewHybridProvider` composes native and CLI paths. Kubernetes/Rancher fall back
when no usable client configuration exists; Nomad falls back before execution
when the task is omitted or the WebSocket endpoint cannot be reached; Docker
and Podman fall back when the requested local socket is absent, refused, or
bypassed by an explicit CLI context/connection. HTTP authorization, target,
TLS configuration, and protocol errors never silently downgrade. Discovery
inspects metadata without connecting: kubeconfig/in-cluster files and verified
Docker/Podman sockets can make a native transport available, while a CLI binary
remains independent safe-path evidence.

## Discovery and negotiation

`containerstream.Discoverer` scores bounded host evidence:

- configured environment such as `KUBECONFIG`, `NOMAD_ADDR`, `DOCKER_HOST`, or
  `CONTAINER_RUNTIME_ENDPOINT`;
- standard Docker, rootless Podman, containerd, CRI-O, and K3s sockets;
- readable kubeconfig, K3s kubeconfig, and in-cluster service-account files;
- executable paths for `kubectl`, `k3s`, `crictl`, `docker`, `podman`, and
  `nomad`.

Inspect the result with:

```bash
wv container-provider status
wv container-provider status --json
```

The default mode is `locked`: discovery happens once per router/agent lifetime
and in-flight and later requests keep the same provider. This avoids a host
changing semantics merely because a socket or binary appears mid-session. A
controlled agent reload can call `Router.Refresh`.

Dynamic hosts can opt into request-time negotiation:

```bash
export WEAVERSSH_CONTAINER_DISCOVERY_MODE=per-request
```

An operator can lock a provider with `WEAVERSSH_CONTAINER_PROVIDER`, `--provider`,
or a request-scoped `?provider=NAME` URI hint. A request hint does not mutate the
agent's locked selection.

## Security and routing boundaries

- URI endpoint, target, option, and path segments are length-bounded and reject
  traversal, NUL/newline injection, flag-shaped target values, and encoded
  segment separators.
- Commands use explicit argument vectors and an argument terminator; provider
  values are never evaluated by a shell.
- Provider discovery does not change SSH authentication, signed node context,
  `WVHOP`, endpoint policy, or the local-first/read-only VFS default.
- Runtime and scheduler authorization remains with the configured Docker,
  Podman, Kubernetes/CRI, or Nomad client identity. WeaverSSH does not broaden
  those permissions.
- Rootless Podman evidence receives a stronger score than a system-wide engine
  when both are usable, matching WeaverSSH's user-space model.
- Process execution is default-deny and policy-named. The synthetic filesystem
  never turns a `ctl` payload into a shell command.
- Session limits, bounded control payloads, configurable stdin byte limits,
  single-open streams, and explicit teardown bound resource use.
- Optional signal and resize operations require provider capabilities; CLI
  wrappers never claim remote-process control they cannot guarantee.
- Detachable terminals additionally require exact-exec termination; closing a
  transport is not treated as proof that its remote process stopped.

## Open-source component boundary

The built-in Kubernetes transport deliberately reuses Apache-2.0
`k8s.io/client-go/tools/remotecommand` instead of reimplementing WebSocket/SPDY
channel negotiation. Nomad's protocol is small and already rides the
repository's Gorilla WebSocket dependency, so importing the full Nomad client
SDK would add weight without transferring lifecycle ownership.

tmux, abduco, dtach/atch, and Zellij were evaluated as possible detachable
session owners. They are not core dependencies. tmux and the small detach tools
own private Unix sockets, are not native Windows backends, and would duplicate
the authenticated attachment generation, replay buffer, TTL, and recording
state already owned by `terminalsession.Manager`. More importantly, placing a
container CLI under a local PTY does not prove that killing the wrapper kills
the remote exec process. `github.com/containerd/console` is similarly useful
for Unix local PTYs but its `NewPty` operation is unavailable on Windows and it
cannot strengthen remote-process termination semantics.

An embedded deployment may still inject a trusted tmux-like implementation via
`TerminalServiceConfig.Spawner`. That plugin receives only the final-node
policy-authorized target and argv. WeaverSSH remains responsible for identity,
resume-token binding, session generations, TTL, replay, and recording; the
plugin must truthfully implement remote PTY resize and teardown. The command-
line default always uses `ContainerSpawner` and opens no tmux socket, listener,
or static forward.

## Standards alignment

This boundary follows the Adapter Pattern: incompatible orchestration clients
are converted to one caller-facing stream contract. It also mirrors the way
Kubernetes uses its [Container Runtime Interface](https://kubernetes.io/docs/concepts/architecture/cri/)
to isolate kubelet from runtime implementations. The runtime families share
the lifecycle vocabulary standardized by the
[OCI Runtime Specification](https://github.com/opencontainers/runtime-spec),
while their supported streaming commands remain adapter-specific:
[kubectl exec](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_exec/),
[docker container exec](https://docs.docker.com/reference/cli/docker/container/exec/),
[podman exec](https://docs.podman.io/en/latest/markdown/podman-exec.1.html), and
[nomad alloc exec](https://developer.hashicorp.com/nomad/commands/alloc/exec).
Podman's native [Libpod REST API](https://docs.podman.io/en/latest/_static/api.html)
defines per-exec start, resize, inspect, and forced removal independently of
the Docker-compatible endpoints.

The synthetic hierarchy follows the Plan 9 process-filesystem model: the
official [`proc(3)` manual](https://9p.io/sys/man/vol1.pdf) describes per-process
directories, read-only status, and textual control writes. Standard stream and
process behavior follows
[POSIX.1-2017](https://pubs.opengroup.org/onlinepubs/9699919799/). Kubernetes
documents CRI `Exec` as preparation of a streaming endpoint in its
[CRI streaming explanation](https://kubernetes.io/blog/2024/05/01/cri-streaming-explained/).
For current Kubernetes clients, WebSockets replaced SPDY as the default
streaming transport in Kubernetes 1.31, while the provider contract remains
transport-neutral; see the official
[WebSocket transition](https://kubernetes.io/blog/2024/08/20/websockets-transition/).
