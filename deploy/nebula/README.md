# Minimal Nebula deployment for WeaverSSH

This directory contains deployment examples and an offline bootstrap helper, not a
managed Nebula control plane. Nebula remains an optional private IP underlay for the
ordinary OpenSSH command started by `wv session-host`.

Topology:

```text
lighthouse-1       10.80.0.1
developer-laptop   10.80.0.10
dev-node-1         10.80.0.20
```

## Offline certificate and configuration bundle

Install a tested `nebula-cert` executable on an offline or otherwise trusted machine,
then run:

```bash
sh ./deploy/nebula/bootstrap-pki.sh \
  --out-dir /secure/offline/weaverssh-development \
  --lighthouse-endpoint lighthouse.example.net:4242
```

The target directory must not already exist. The helper stages the complete output and
renames it into place only after all expected files have been created. It produces:

```text
offline-ca/ca.crt
offline-ca/ca.key
lighthouse-1/{ca.crt,host.crt,host.key,config.yaml}
developer-laptop/{ca.crt,host.crt,host.key,config.yaml}
dev-node-1/{ca.crt,host.crt,host.key,config.yaml}
manifest.txt
DISTRIBUTION.txt
```

`ca.key` exists only under `offline-ca/`, and private keys are mode `0600`. The helper
refuses existing output, duplicate names or CIDRs, unsafe values, and reserved output
names. It does not download Nebula, start services, open firewall ports, or issue any
WeaverSSH credential.

Copy only each host directory's four files to that host. Keep `offline-ca/ca.key`
offline. Install host files under `/etc/nebula`, retaining mode `0600` for `host.key`.

Validate the bootstrap logic without real keys using:

```bash
sh tools/verification/nebula_bootstrap_test.sh
```

## Independent trust layers

The groups `lighthouse`, `weaverssh-client`, and `weaverssh-node` control only network
reachability. WeaverSSH continues to authorize signed node contexts and endpoint
capabilities independently. The CA key is never copied into a WeaverSSH node context,
`WVHOP`, authproof, or destination policy.

`NEBULA_VERSION` records the baseline used by these examples. Installation and updates
remain an operator responsibility; WeaverSSH never downloads or embeds Nebula at
runtime.

Replace the documentation-only lighthouse public address before deployment. Only the
lighthouse needs public UDP 4242. Public TCP 22 on `dev-node-1` should be blocked after
overlay SSH has been verified.
