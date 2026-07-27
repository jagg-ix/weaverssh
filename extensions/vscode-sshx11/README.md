# SSHX11 Ops (VS Code Extension)

SSHX11 Ops provides command-palette workflows for running SSHX11 operations from
VS Code through the existing `tools/verification/sshx11_ops.sh` operator script.

It is designed for multi-profile connectivity workflows:

- local SOCKS fallback
- reverse SOCKS for remote extension-host egress
- local WebDAV, repo-native 9P VFS service, and extension-host profile verification

## What it does

- Runs core SSHX11 lifecycle commands (`service-start`, `service-stop`, `status-local`).
- Runs extension-host routing commands (`vscode-profile-gen`, `verify-extension-hosts`).
- Runs reverse SOCKS smoke flow with prompted host/user/key inputs.
- Provides a popup Configure widget with placement control (`auto|bottom|top`).
- Exposes an extension API + hidden command API for other VS Code extensions.
- Provides a reusable programmatic UI driver (`src/ui-api.ts`) so command-palette UI and external callers share one action surface.
- Supports `ssh-agent` and PuTTY/Pageant/antagent-style IdentityAgent routing for reverse SOCKS and remote probes.
- Opens the SSHX11 VS Code workflow document directly from VS Code.
- Starts, stops, plans, and inspects the repo-native `wv-9p` service through the same UI/API path.

## Requirements

- VS Code `^1.90.0`
- Workspace opened at repository root (or with correct `sshx11.opsScriptPath`)
- Shell runtime able to execute `tools/verification/sshx11_ops.sh`
- Dependencies required by selected SSHX11 operations (SSH client, Python tooling, etc.)

## Quick Start

1. Open this repository as your VS Code workspace.
2. Build extension:

```bash
cd extensions/vscode-sshx11
npm install
npm run build
npm run smoke:api
```

3. Press `F5` in this extension folder to launch an Extension Development Host.
4. Open Command Palette and run:
   - `SSHX11: Configure`
   - `SSHX11: Start Services`
   - `SSHX11: Status (Local)`
   - `SSHX11: Generate VS Code Profiles`
   - `SSHX11: Verify Extension Hosts`
   - `SSHX11: Start 9P Service`
   - `SSHX11: 9P Service Status`

## Command Catalog

The extension commands map directly to `sshx11_ops.sh` subcommands.

| VS Code Command | Script Subcommand | Typical Use |
|---|---|---|
| `SSHX11: Configure` | n/a | Open popup widget to configure extension settings (SSH, proxy, agent, runtime, logging). |
| `SSHX11: Start Services` | `service-start` | Start control/data plane daemons. |
| `SSHX11: Stop Services` | `service-stop` | Stop control/data plane daemons. |
| `SSHX11: Status (Local)` | `status-local` | Check service + policy + state health. |
| `SSHX11: Start SOCKS Fallback` | `socks-fallback-start` | Enable proxy mode when direct routing is unavailable. |
| `SSHX11: Generate VS Code Profiles` | `vscode-profile-gen --profile all --output-dir .vscode/sshx11` | Create local/remote/reverse-socks env profiles. |
| `SSHX11: Verify Extension Hosts` | `verify-extension-hosts [--ssh-config ...] [--proxy-jump ...] [--proxy-command ...] [--agent-mode ...] [--forward-agent] [--identity-agent ...] [--remote-platform ...] [--remote-shell-bin ...] [--remote-shell-login] [--remote-python-bin ...] [--ssh-verbosity ...] [--ssh-log-level ...] [--ssh-log-file ...]` | Validate profile shape and probe paths (including proxied SSH, agent transport, runtime profile, and SSH logging flags). |
| `SSHX11: Reverse SOCKS Smoke` | `reverse-socks-smoke --host ... --user ... [--identity-file ...] [--ssh-config ...] [--proxy-jump ...] [--proxy-command ...] [--agent-mode ...] [--forward-agent] [--identity-agent ...] [--remote-platform ...] [--remote-shell-bin ...] [--remote-shell-login] [--remote-python-bin ...] [--ssh-verbosity ...] [--ssh-log-level ...] [--ssh-log-file ...] [--insecure-hostkey]` | End-to-end reverse-SOCKS start/status/remote-probe flow with runtime + logging controls. |
| `SSHX11: Start WebDAV` | `webdav-start` | Start lightweight local WebDAV endpoint. |
| `SSHX11: Start 9P Service` | `9p-start` | Start the repo-native read-only `wv-9p` service for VFS workflows. |
| `SSHX11: 9P Service Status` | `9p-status` | Inspect the `wv-9p` service state, PID, port, root, and log path. |
| `SSHX11: Stop 9P Service` | `9p-stop` | Stop the managed `wv-9p` service. |
| `SSHX11: Plan 9P Service` | `9p-plan` | Show the `wv-9p` launch command and missing prerequisites without starting it. |
| `SSHX11: Open Workflow Documentation` | n/a | Opens `docs/workstation/SSHX11_VSCODE_EXTENSION_NETWORK_WORKFLOWS.md`. |

Reference files:

- `docs/command-catalog.md`
- `data/command-map.json`

## API for Other Extensions

Other extensions can consume this extension as an API provider:

```ts
const ext = vscode.extensions.getExtension<import("vscode-sshx11").SSHX11ExtensionApi>("local.vscode-sshx11");
const api = await ext?.activate();
const actions = api?.listUiActions();
const statusAction = api?.describeUiAction("statusLocal");
await api?.runUiAction("verifyExtensionHosts");
await api?.runNamedCommand("statusLocal");
const settings = api?.getSettingsSnapshot();
```

Exported API capabilities:

- `showConfigure()`
- `runOpsCommand(subcommand, args?)`
- `runNamedCommand(name, request?)`
- `runReverseSocksSmoke(request?)`
- `getSettingsSnapshot()`
- `listUiActions()`
- `describeUiAction(name)`
- `runUiAction(name, request?)`
- `listFeaturePlugins(filter?)`
- `discoverFeaturePlugins(filter?)`
- `describeFeaturePlugin(id)`
- `onDidRunCommand` event stream

Command-based API (callable via `vscode.commands.executeCommand`):

- `sshx11.api.getSettingsSnapshot`
- `sshx11.api.runOpsCommand`
- `sshx11.api.runNamedCommand`
- `sshx11.api.showConfigure`
- `sshx11.api.listUiActions`
- `sshx11.api.describeUiAction`
- `sshx11.api.runUiAction`
- `sshx11.api.listFeaturePlugins`
- `sshx11.api.discoverFeaturePlugins`
- `sshx11.api.describeFeaturePlugin`

Tiny end-to-end consumer sample:

- `examples/consumer-extension.sample.ts`


### Programmatic UI Driver

`src/ui-api.ts` is the canonical action library for the extension UI. It lists every user-facing action, describes its command ID/category/kind, and resolves executable plans from a settings snapshot. The VS Code command-palette entries call `runUiAction(...)`, so automated callers and human UI interactions use the same behavior path.

Typical uses:

- Discover what the UI can do with `listUiActions()`.
- Inspect one action before launching it with `describeUiAction("reverseSocksSmoke")`.
- Launch a UI behavior without opening the command palette with `runUiAction("statusLocal")`.
- Manage the repo-native 9P service with `runUiAction("ninepStart")`, `runUiAction("ninepStatus")`, and `runUiAction("ninepStop")`.
- Launch prompted workflows non-interactively by passing request data, for example `runUiAction("reverseSocksSmoke", { host, user, identityFile })`.
- Use the same action surface outside VS Code through `sshx11d`: `GET /v1/uiActions`, `GET /v1/uiActions/{name}`, and `POST /v1/runUiAction`.
- Use the same feature discovery surface outside VS Code through `sshx11d`: `GET /v1/featurePlugins`, `GET /v1/featurePlugins/discover`, and `GET /v1/featurePlugins/vfs.9p`.

## Settings

Supported settings:

- `sshx11.opsScriptPath`
- `sshx11.showStatusBarConfigure`
- `sshx11.widgetLocation` (`auto`, `bottom`, `top`)
- `sshx11.verbose`
- `sshx11.defaultRemoteHost`
- `sshx11.defaultRemoteUser`
- `sshx11.defaultIdentityFile`
- `sshx11.defaultSshConfigPath`
- `sshx11.defaultSshProxyJump`
- `sshx11.defaultSshProxyCommand`
- `sshx11.sshVerbosity` (`0..3`)
- `sshx11.sshLogLevel`
- `sshx11.sshLogFile`
- `sshx11.agentMode` (`auto`, `require`, `disable`)
- `sshx11.forwardAgent`
- `sshx11.identityAgent`
- `sshx11.sshClientAdapter` (`auto`, `puttyPlink`, `kittySsh`, `windowsOpenSSH`, `cygwinOpenSSH`, `gitForWindowsOpenSSH`, `msys2OpenSSH`, `wslOpenSSH`, `bitviseSshClient`, `secureCRT`, `xshell`, `mobaxtermSsh`, `tectiaSsh`, `termiusSsh`, `winscp`, `openSSH`, `dropbear`, `paramikoPython`, `asyncsshPython`)
- `sshx11.virtualizationLayer` (`auto`, `none`, `wsl`, `hyperV`, `vmware`, `virtualBox`, `parallels`, `qemuKvm`, `libvirt`, `docker`, `podman`, `lxc`, `multipass`, `lima`, `colima`, `utm`)
- `sshx11.setupKind` (`auto`, `localUser`, `workspace`, `organizationManaged`, `manual`)
- `sshx11.organizationProvider` (`none`, `github`, `gitlab`, `okta`, `azureAD`, `customMcp`, `localPolicy`)
- `sshx11.chainConnector` (`none`, `vscodeExtension`, `localContextMcp`, `sshConfig`, `enterpriseConnector`)
- `sshx11.organizationConfigPath`
- `sshx11.remotePlatform` (`auto`, `linux`, `linux-generic`, `linux-headless`, `linux-gui`, `macos`, `freebsd`, `freebsd-generic`, `freebsd-gui`, `openbsd`, `aix`, `solaris`, `zos`, `generic`)
- `sshx11.remoteShellBin`
- `sshx11.remoteShellLogin`
- `sshx11.remotePythonBin`
- `sshx11.insecureHostKey`

Sample `settings.json`:

```json
{
  "sshx11.opsScriptPath": "tools/verification/sshx11_ops.sh",
  "sshx11.showStatusBarConfigure": true,
  "sshx11.widgetLocation": "auto",
  "sshx11.verbose": false,
  "sshx11.defaultRemoteHost": "203.0.113.20",
  "sshx11.defaultRemoteUser": "root",
  "sshx11.defaultIdentityFile": "~/.ssh/id_ed25519",
  "sshx11.defaultSshConfigPath": "~/.ssh/config",
  "sshx11.defaultSshProxyJump": "bastion.example.com",
  "sshx11.defaultSshProxyCommand": "",
  "sshx11.sshVerbosity": 1,
  "sshx11.sshLogLevel": "VERBOSE",
  "sshx11.sshLogFile": "/tmp/sshx11-ssh.log",
  "sshx11.agentMode": "auto",
  "sshx11.forwardAgent": false,
  "sshx11.identityAgent": "env:SSH_AUTH_SOCK",
  "sshx11.remotePlatform": "auto",
  "sshx11.remoteShellBin": "sh",
  "sshx11.remoteShellLogin": true,
  "sshx11.remotePythonBin": "",
  "sshx11.insecureHostKey": false
}
```

`sshx11.widgetLocation` behavior:

- `auto`: uses bottom status bar (most common for this kind of extension quick action).
- `bottom`: forces status bar placement.
- `top`: shows Configure action in top window-frame action areas and hides status bar widget.

See also:

- `examples/sshx11.settings.json`

## Security Notes

- Keep `sshx11.insecureHostKey` disabled outside temporary local testing.
- Prefer explicit identity file paths and per-host SSH config.
- For strict agent-only auth, set `sshx11.agentMode` to `require`.
- For PuTTY/Pageant/antagent bridges, set `sshx11.identityAgent` to a bridge value (for example `pageant:`).
- Use least-privilege credentials for remote operations.
- Treat generated profile/proxy files as operational config and review before sharing.

## Troubleshooting

`Command fails immediately`:

- Confirm workspace root and `sshx11.opsScriptPath`.
- Confirm script executable permission:
  - `chmod +x tools/verification/sshx11_ops.sh`

`Reverse SOCKS smoke fails`:

- Verify remote host/user/key values.
- Test SSH connectivity outside VS Code first.
- If needed for temporary local tests, enable `sshx11.insecureHostKey`.

`Profiles generated but validation fails`:

- Re-run `SSHX11: Generate VS Code Profiles`.
- Re-run `SSHX11: Verify Extension Hosts`.
- Inspect `verification_results/stack_audits/sshx11_extension_host_paths_smoke.json`.

## Development

```bash
cd extensions/vscode-sshx11
npm install
npm run build
```

Watch mode:

```bash
npm run watch
```

Package extension:

```bash
npm run package
```

## Related Workspace Docs

- `docs/developer_system_architecture_guide.md`
- `docs/workstation/CODEX_VSCODE_MCP_INTEGRATION.md`
