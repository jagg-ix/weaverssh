<div align="center">

# weaverssh

**Supercharge SSH** — move files, TCP/UDP, and events across the SSH session you already have.
*SSH, just the way it was always meant to be.*

![Go](https://img.shields.io/badge/Go-1.23-00ADD8?logo=go&logoColor=white)
&nbsp;![CI](https://github.com/jagg-ix/weaverssh/actions/workflows/ci.yml/badge.svg)
&nbsp;![Release](https://img.shields.io/github/v/release/jagg-ix/weaverssh?sort=semver&logo=github)
&nbsp;![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)
&nbsp;![Platforms](https://img.shields.io/badge/platforms-linux%20%7C%20macOS%20%7C%20windows%20%7C%20freebsd-lightgrey)

</div>

## Why

- **Remote apps are unreachable.** `ssh -L`/`-R` needs free ports and your attention, is often disabled on hardened `sshd`, and doesn't compose across jump hosts.
- **`scp` stages files on every hop.** Routing data through bastions costs space and widens the security surface.
- **No unified view.** `scp` is point-to-point — there is no single namespace across your hosts.

weaverssh reuses the SSH connection you already have: it starts over standard X11 forwarding, upgrades that channel to a WebSocket, and multiplexes files, TCP, and UDP over it — no `-L`/`-R`, no extra ports, no daemon left on the remote host.

## How it works

```text
wv session-host   allocate a private X display + cookie, then run your `ssh -X`
ssh -X            your normal SSH; sshd forwards the X11 channel
wv attach         verify the cookie, upgrade to a WebSocket, multiplex files/tcp/udp
```

Traffic is never staged on a jump host.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/jagg-ix/weaverssh/main/install.sh | sh
```

Prebuilt binaries and `.deb`/`.rpm`/`.apk` are on each
[release](https://github.com/jagg-ix/weaverssh/releases). On Windows:
`irm https://raw.githubusercontent.com/jagg-ix/weaverssh/main/install.ps1 | iex`.
From source: `make build` (needs Go 1.23+ and `xauth`).

## Usage

Once per remote host, let sshd forward the session identity:

```bash
echo 'AcceptEnv WVORIGIN WVHOP' | sudo tee /etc/ssh/sshd_config.d/60-weaverssh.conf
sudo systemctl restart ssh
```

Then, from your workstation:

```bash
wv keygen --private wv.key --public wv.key.pub
wv node-context sign-services --nodes workstation,compute --node workstation \
  --capabilities node.context,vfs.mesh,socks.proxy --private-key-file wv.key --out ws.ctx
# sign compute.ctx the same way (--node compute), then copy wv.key.pub + compute.ctx to the host
wv session-host --root ~/shared --node-context ws.ctx --public-key-file wv.key.pub -- ssh -X user@compute
```

In the shell that opens on `compute`:

```bash
wv attach --node-context ~/compute.ctx --public-key-file ~/wv.key.pub --root ~/shared --read-only=false
```

`scripts/wv-single-hop-example.sh` scripts this end-to-end; `wv help` lists every command.

## Files across your nodes

Each attached node is a named prefix in one filesystem view; data streams node-to-node, never staged on a bastion in between:

```bash
wv cp report.pdf compute:/inbox/report.pdf                          # local file → a remote node
wv ls  compute:/inbox                                               # list a remote directory
wv cat endpoint:/status.json                                        # read the far end of the chain
wv session-proxy --node compute --auth none --listen 127.0.0.1:1080 # SOCKS5 egress via that node
```

## Connection profiles & agents

`wv connections scan --import` autodetects hosts from `~/.ssh/config`, PuTTY sessions, and
`known_hosts` into reusable profiles. `wv agent-bridge` lets a WSL2/Linux ssh-agent use keys
held by a Windows agent (OpenSSH or Pageant). See `wv connections -h` and `wv agent-bridge -h`.

## Security

- The X11 cookie is verified before the WebSocket upgrade.
- Nodes register with signed contexts bound to the session; capabilities are explicit.
- TCP/UDP egress is deny-by-default and allowlisted per session.
- The final host performs each dial; intermediate hops only relay.

## License

[Apache 2.0](LICENSE).
