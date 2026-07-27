# weaverssh examples

These examples are intended to be copied and adapted. They use the signed node
IDs from each node context; they do not infer SSH host names from session paths.

## Before running an example

Build or install `wv`, then verify the basic prerequisites:

```bash
wv version
command -v ssh
command -v xauth
```

For real SSH sessions, every receiving SSH server must accept `WVORIGIN`:

```text
AcceptEnv WVORIGIN
```

Recursive sessions also require `WVHOP` and agent forwarding:

```text
AcceptEnv WVORIGIN WVHOP
```

Keep issuer private keys and SOCKS principal private keys on trusted systems.
The examples use loopback listeners and deny-by-default destination lists.

## Examples

- [Single-hop session](single-hop-session.md): create two signed node contexts,
  start `wv session-host`, attach on the remote node, and copy files in both
  directions.
- [Recursive session](recursive-session.md): traverse
  `workstation-42 -> jump-a -> compute-node` with signed SSHSIG hop records.
- [Proof-aware SOCKS5](socks5-proof.md): require a principal proof before the
  final node opens a TCP connection.

The companion script `scripts/wv-single-hop-example.sh` prepares a local
single-hop workspace and prints or executes the host command. It defaults to
plan mode so it does not modify SSH servers or start a session unexpectedly.

## Session path rules

A session path is always relative to a root explicitly exported by `wv`:

```text
NODE:/relative/path
node:NODE:/relative/path
```

Examples:

```bash
wv ls workstation-42:/
wv cp ./input.dat compute-node:/jobs/input.dat
wv cp compute-node:/results/result.bin ./result.bin
```

`user@host:/path` remains normal SSH/SCP syntax. `NODE:~/path` is undefined.
