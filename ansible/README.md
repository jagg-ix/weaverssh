# weaverssh Ansible Install Support

This directory contains an Ansible role for installing `wv` from the
source-free binary archive produced by `make binary-dist`. It supports POSIX SSH
hosts, local Docker/compatible containers, and Kubernetes pods.

The default install path is user-home only:

```text
~/.weaverssh/bin/wv
```

No root privileges are required by default.

## Build The Archive On The Controller

Build the target artifact first:

```bash
make binary-dist BINARY_DIST_TARGET=linux/amd64
```

Optional reproducible/signed release build:

```bash
make binary-dist \
  BINARY_DIST_TARGET=linux/amd64 \
  BINARY_DIST_SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) \
  BINARY_DIST_SIGN_KEY=release.key
```

## Install From A Controller-Local Archive

Create an inventory:

```ini
[weaverssh_targets]
linode1 ansible_host=203.0.113.10 ansible_user=kb
linode2 ansible_host=203.0.113.20 ansible_user=kb
```

Run the playbook:

```bash
ansible-playbook \
  -i inventory.ini \
  ansible/playbooks/install_wv.yml \
  -e weaverssh_version=0.1.0 \
  -e weaverssh_release=1 \
  -e weaverssh_archive_path=dist/binary/weaverssh-0.1.0-1-linux-amd64.tar.gz \
  -e weaverssh_archive_checksum=<sha256>
```

The checksum may be raw hex or `sha256:<hex>`.

## Install Into A Docker Container

Build a Linux archive for the container architecture, then copy only `bin/wv` into
an already-running local container. The role probes `uname -m` inside the
container unless `weaverssh_target_arch` is set explicitly:

```bash
make binary-dist BINARY_DIST_TARGET=linux/amd64
make ansible-install-docker-plan \
  ANSIBLE_DOCKER_CONTAINER=<container> \
  ANSIBLE_WV_ARCHIVE=dist/binary/weaverssh-0.1.0-1-linux-amd64.tar.gz \
  ANSIBLE_WV_CHECKSUM=<sha256>
make ansible-install-docker \
  ANSIBLE_DOCKER_CONTAINER=<container> \
  ANSIBLE_WV_ARCHIVE=dist/binary/weaverssh-0.1.0-1-linux-amd64.tar.gz \
  ANSIBLE_WV_CHECKSUM=<sha256>
```

Use `ANSIBLE_DOCKER_RUNTIME=podman` for Podman-compatible targets. Container
installs default to `/tmp/.weaverssh/bin/wv` because the container filesystem may
be ephemeral. Bake the binary into the image or mount a persistent volume when it
must survive container recreation.

## Install Into A Kubernetes Pod

Build a Linux archive for the pod architecture, then copy only `bin/wv` into an
already-running pod using `kubectl cp` and verify it with `kubectl exec`. The
role probes `uname -m` inside the pod unless `weaverssh_target_arch` is set
explicitly:

```bash
make binary-dist BINARY_DIST_TARGET=linux/amd64
make ansible-install-k8s-plan \
  ANSIBLE_K8S_NAMESPACE=<namespace> \
  ANSIBLE_K8S_POD=<pod> \
  ANSIBLE_K8S_CONTAINER=<container-if-needed> \
  ANSIBLE_WV_ARCHIVE=dist/binary/weaverssh-0.1.0-1-linux-amd64.tar.gz \
  ANSIBLE_WV_CHECKSUM=<sha256>
make ansible-install-k8s \
  ANSIBLE_K8S_NAMESPACE=<namespace> \
  ANSIBLE_K8S_POD=<pod> \
  ANSIBLE_K8S_CONTAINER=<container-if-needed> \
  ANSIBLE_WV_ARCHIVE=dist/binary/weaverssh-0.1.0-1-linux-amd64.tar.gz \
  ANSIBLE_WV_CHECKSUM=<sha256>
```

For single-container pods, omit `ANSIBLE_K8S_CONTAINER`. Pod installs are also
runtime copies into `/tmp/.weaverssh/bin/wv`; use an init container, image layer,
or mounted volume for persistent production deployment.

## Install From A Release URL

Host the archive and checksum sidecar in an internal artifact store, then run:

```bash
ansible-playbook \
  -i inventory.ini \
  ansible/playbooks/install_wv.yml \
  -e weaverssh_release_base_url=https://artifacts.example.invalid/weaverssh \
  -e weaverssh_version=0.1.0 \
  -e weaverssh_release=1 \
  -e weaverssh_archive_checksum=sha256:<sha256>
```

## Variables

| Variable | Default | Meaning |
| --- | --- | --- |
| `weaverssh_target_type` | `posix` | Install path: `posix`, `docker`, or `kubernetes`. |
| `weaverssh_install_dir` | `{{ ansible_env.HOME }}/.weaverssh/bin` | Final POSIX `wv` install directory. |
| `weaverssh_cache_dir` | `{{ ansible_env.HOME }}/.weaverssh/cache` | Remote archive/extract cache. |
| `weaverssh_archive_path` | empty | Controller-local archive to copy. |
| `weaverssh_release_base_url` | `https://weaverssh.com/releases` | Base URL used when no local archive is provided. |
| `weaverssh_archive_url` | empty | Full archive URL override. |
| `weaverssh_archive_checksum` | empty | Optional SHA-256 verification. |
| `weaverssh_update_shell_rc` | `false` | Add install dir to shell startup file. |
| `weaverssh_run_smoke_test` | `true` | Run `wv version` and `wv help` after install. |
| `weaverssh_target_os` / `weaverssh_target_arch` | empty | Override target label detection. |
| `weaverssh_container_install_dir` | `/tmp/.weaverssh/bin` | Final `wv` install directory for Docker/Kubernetes targets. |
| `weaverssh_docker_runtime` | `docker` | Docker-compatible CLI to use, for example `docker` or `podman`. |
| `weaverssh_docker_container` | empty | Running container name or ID for Docker target installs. |
| `weaverssh_kubectl` | `kubectl` | Kubernetes CLI to use for pod target installs. |
| `weaverssh_kubernetes_namespace` | `default` | Namespace for Kubernetes pod installs. |
| `weaverssh_kubernetes_pod` | empty | Pod name for Kubernetes pod installs. |
| `weaverssh_kubernetes_container` | empty | Optional container name for multi-container pods. |

## Supported Targets

This role supports three target families. POSIX SSH targets use Ansible builtin modules:

- Linux
- macOS
- FreeBSD
- OpenBSD

Docker and Kubernetes installs run from the controller against an already-running
container or pod using `docker`/`podman` or `kubectl`. They do not require source
code inside the target runtime.

Windows should use a separate WinRM role path because the correct modules are
`ansible.windows.win_get_url`, `community.windows.win_unzip`, and PowerShell path
handling rather than POSIX `copy`/`unarchive`.
