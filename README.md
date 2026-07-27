<div align="center">

# weaverssh
supercharge ssh
Route files, connections, and events to your workstation
SSH, just the way it was always meant to be.

![Go](https://img.shields.io/badge/Go-1.23-00ADD8?logo=go&logoColor=white)
&nbsp;![CI](https://github.com/jagg-ix/weaverssh/actions/workflows/ci.yml/badge.svg)
&nbsp;![Release](https://img.shields.io/github/v/release/jagg-ix/weaverssh?sort=semver&logo=github)
&nbsp;![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)
&nbsp;![Platforms](https://img.shields.io/badge/platforms-linux%20%7C%20macOS%20%7C%20windows%20%7C%20freebsd-lightgrey)

</div>

## First Challenge: Applications on your workstation are unreachable from remote side
That's it, ssh try to solve this by having `ssh -L` / `ssh -R`, it helps but doesnt help if i need to actually work
instead of dealing with this delays while production needs to be fix and the client is on the phone asking for status, 

## Second Challenge: Cybersecurity and storage, SCP intermediary host 
You can SSH into a host — often through one or more bastions —  but to copy a file you need access and space available

## Third Challenge: SCP lacks a Commons VFS
Unlike systems that provide a unified virtual file system, SCP offers no way to present files and directories under a single hierarchy. Each transfer is link to a specific host and path, with no dynamic mapping or abstraction. As a result, there is no flexibility in how a user can obtain or construct a coherent view of remote files — every operation remains isolated, point‑to‑point, and disconnected from a broader namespace.
## How it works

```text
wv session-host   allocate a private X display + auth cookie, then run your `ssh -X`
ssh -X            your normal SSH; sshd forwards the X11 channel
wv attach         verify the X11 cookie, upgrade the channel to a WebSocket,
                  and multiplex control / files / tcp / udp streams over it
```

Traffic is never staged on a jump host. A local Unix socket lets other `wv` commands on the
same account reuse the live session.

## Install

**Quick install** (Linux, macOS, FreeBSD/OpenBSD/NetBSD) — downloads the `wv`
binary for your OS/arch and verifies its SHA-256 against the release checksums:

```bash
curl -fsSL https://raw.githubusercontent.com/jagg-ix/weaverssh/main/install.sh | sh
# or: wget -qO- https://raw.githubusercontent.com/jagg-ix/weaverssh/main/install.sh | sh
```

Pin a version or install directory with `WEAVERSSH_VERSION=v0.1.1` /
`WEAVERSSH_BIN_DIR=~/.local/bin`. On Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/jagg-ix/weaverssh/main/install.ps1 | iex
```

**Linux packages** — `.deb`, `.rpm`, and `.apk` for amd64, arm64, 386, ppc64le,
s390x, and riscv64 are attached to every
[release](https://github.com/jagg-ix/weaverssh/releases):

```bash
sudo dpkg -i weaverssh_0.1.1_linux_amd64.deb                  # Debian / Ubuntu
sudo rpm  -i weaverssh_0.1.1_linux_amd64.rpm                  # RHEL / Fedora / SUSE
sudo apk add --allow-untrusted weaverssh_0.1.1_linux_amd64.apk # Alpine
```

**From source** — requires Go 1.23+, `make`, and `xauth` (for real SSH/X11 sessions):

```bash
git clone https://github.com/jagg-ix/weaverssh.git
cd weaverssh
make build
./build/bin/wv version
```

## Usage

On your workstation, generate a signing key and a signed context for each node in the
path — here your workstation and one remote host, `compute`:

```bash
wv keygen --private weaverssh.key --public weaverssh.key.pub

for node in workstation compute; do
  wv node-context sign-services \
    --nodes workstation,compute \
    --node "$node" \
    --capabilities node.context,vfs.mesh,socks.proxy \
    --private-key-file weaverssh.key \
    --out "$node.context.json"
done
```

Copy the public key and the remote's own context to `compute` — the private key never
leaves your workstation:

```bash
scp weaverssh.key.pub compute.context.json user@compute:~/
```

`compute` receives a signed `WVORIGIN` identity over SSH, so let its sshd accept it once
(on `compute`, as root):

```bash
echo 'AcceptEnv WVORIGIN WVHOP' | sudo tee /etc/ssh/sshd_config.d/60-weaverssh.conf
sudo systemctl restart ssh   # or: sudo service ssh restart
```

(Or skip the sshd change and pass `--wvorigin workstation` to `wv attach` below.)

Start the session from your workstation. `session-host` sets up the transport and runs
your `ssh -X`, which opens a shell on `compute`:

```bash
mkdir -p ~/shared
wv session-host \
  --root ~/shared \
  --tcp-allow '127.0.0.1:8080,*.corp.internal:443' \
  --node-context workstation.context.json \
  --public-key-file weaverssh.key.pub \
  -- ssh -X user@compute
```

In that shell on `compute`, attach. The `--root` directory must exist; `--read-only=false`
lets other nodes write into it (for example, to receive a `wv cp`):

```bash
mkdir -p ~/compute-shared
wv attach \
  --node-context ~/compute.context.json \
  --public-key-file ~/weaverssh.key.pub \
  --root ~/compute-shared --read-only=false \
  --tcp-allow '127.0.0.1:3000,db.internal:5432'
```

`wv help` lists every command; `wv <command> -h` shows its flags. For a scripted version
of this single-hop setup, see
[`scripts/wv-single-hop-example.sh`](scripts/wv-single-hop-example.sh).

## Files across your nodes

Once each host in the chain has run `wv attach`, every node becomes a named prefix in a
single filesystem view. Any `wv` file command works across it **from any node**, and data
streams node-to-node through the session — never staged on a bastion in between.

Copy a local file straight onto another node. Run this on `host-bob`:

```bash
wv cp localbobhome/bobdata.txt alicenode:/project/bobdata.txt
```

`localbobhome/bobdata.txt` is a local path on host-bob; `alicenode:/project/…` is alice's
exported root. No `scp`, and no temporary copy on any hop in between.

Copy directly between two remote nodes — neither end is local, and nothing lands on the
machine you run it from:

```bash
wv cp alicenode:/build/app.bin carol-node:/deploy/app.bin
```

The node you run the command on is addressed by a plain local path — no prefix. Remote
nodes use `name:/path`, or the `endpoint` alias for the far end of the chain:

```bash
wv cp  endpoint:/var/log/app.log ./app.log   # pull a file from the far node to here
wv cat endpoint:/status.json                 # read the far end of the chain
```

Browse the view and reach TCP services on a node over the same session:

```bash
wv ls alicenode:/project                                              # list a remote directory
wv session-proxy --node alicenode --auth none --listen 127.0.0.1:1080 # SOCKS5 egress via that node
```

`wv session-proxy` opens a local SOCKS5 listener whose traffic exits on `alicenode`, limited
to that node's `--tcp-allow` list. (`wv connect NODE HOST:PORT` pipes a single connection over
stdio, for use as an `ssh -o ProxyCommand`.)

## Connection profiles and agents

`wv connections scan` autodetects SSH targets from `~/.ssh/config` (with `Include`
resolution), PuTTY saved sessions (including the Windows registry), and `known_hosts`.
`wv connections scan --import` stores them as reusable profiles that `wv connections list`
and `wv connections use` can drive.

The ssh_config source is pluggable — `--ssh-config path | - | fd:N | pipe:PATH | exec:CMD`
(also `WEAVERSSH_SSH_CONFIG_SOURCE`, or a `.wv/config.json`), so the config can come from a
file, stdin, a pipe, or a program rather than only `~/.ssh/config`. A project-local `.wv/`
directory (found by walking up from the working directory) keeps its profiles and path
sequences — `wv connections --nodes 'a->b->c' --name path` — in `.wv/connections.json`.

A path step can also be a selector over a pre-authorized set. Define a group
(`wv connections group set computes --members c1,c2,c3`), use it in a path
(`... -> group:computes`), then resolve it at construction time —
`wv connections resolve path --resolver computes=exec:./pick` (or `--select computes=c2`) —
and a lookup/alias picks one member. The choice is constrained to the group, and with
`--node-context FILE` / `--signed-nodes` to the signed node set, so it never leaves the
authorized topology.

That resolution can also happen **at the node making the hop**: `wv connections next-hop`
finds this node in the path (from its signed `--node-context`) and resolves the following
step against its own authorized set — feeding the concrete target to `session-host`:

```bash
target=$(wv connections next-hop path --node-context node.ctx --ssh \
           --resolver computes=exec:./pick-compute)
wv session-host --node-context node.ctx --public-key-file key.pub -- ssh -X "$target"
```

`wv agent-bridge` forwards a local ssh-agent socket to another agent over the standard
SSH agent protocol — a plain agent socket, the Windows OpenSSH agent, or PuTTY Pageant
(just a different agent implementation). One binary is both ends, so on **WSL2** a Linux
ssh-agent can use keys held by a Windows agent without socat or a separate helper. Install
`wv.exe` on the Windows side, then in WSL2:

```bash
wv agent-bridge --listen ~/.ssh/agent.sock --upstream 'exec:wv.exe agent-bridge --stdio'
export SSH_AUTH_SOCK=~/.ssh/agent.sock
```

The Windows side defaults to the OpenSSH agent pipe; add `--upstream pageant` there to use
Pageant instead. Locally, `wv agent-bridge --listen SOCK --upstream unix:$SSH_AUTH_SOCK`
simply re-exports an existing agent.

## Security

- The X11 cookie is verified before the WebSocket upgrade.
- Nodes register with signed contexts bound to the session; capabilities are explicit.
- TCP/UDP egress is deny-by-default and allowlisted per session.
- The final host performs each dial; intermediate hops only relay.

## License

[Apache 2.0](LICENSE).
