import * as vscode from "vscode";
import { loadNebulaProfile, resolveWorkspacePath, type WeaverSSHWorkspaceProfile } from "../connections/nebulaProfile";
import { formatNebulaStatus, readNebulaStatus, type NebulaStatus } from "../diagnostics/nebulaStatus";
import { readSessionStatus, waitForSession, type SessionRuntimeStatus } from "../session/sessionStatus";

function shellQuote(value: string): string {
  if (value.length === 0) {
    return "''";
  }
  if (!/[^\w@%+=:,./-]/.test(value)) {
    return value;
  }
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function configuredString(name: string, fallback: string): string {
  return String(vscode.workspace.getConfiguration("weaversshNebula").get(name, fallback) ?? fallback).trim();
}

function configuredNumber(name: string, fallback: number): number {
  const value = Number(vscode.workspace.getConfiguration("weaversshNebula").get(name, fallback));
  return Number.isFinite(value) && value > 0 ? value : fallback;
}

async function readWorkspaceProfile(): Promise<{ root: string; path: string; profile: WeaverSSHWorkspaceProfile }> {
  const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!root) {
    throw new Error("open a workspace folder before using the Nebula connection profile");
  }
  const configuredPath = configuredString("profilePath", ".weaverssh/workspace.json");
  const profilePath = resolveWorkspacePath(root, configuredPath);
  return { root, path: profilePath, profile: await loadNebulaProfile(profilePath) };
}

function updateStatusBar(
  item: vscode.StatusBarItem,
  profile: WeaverSSHWorkspaceProfile,
  network: NebulaStatus,
  session?: SessionRuntimeStatus
): void {
  const authenticated = session !== undefined;
  item.text = authenticated
    ? `$(remote) WeaverSSH: ${profile.target_node}`
    : network.ssh_reachable
      ? `$(remote) WeaverSSH: ${profile.target_node} (SSH ready)`
      : `$(warning) WeaverSSH: ${profile.target_node}`;
  item.tooltip = [
    `WeaverSSH: ${profile.target_node}`,
    "Connection: SSH over Nebula",
    `Overlay address: ${network.overlay_address || network.resolved_host || "unresolved"}`,
    `Session: ${authenticated ? "authenticated" : "not active"}`,
    `Route: ${session?.routeLabel || (network.ssh_reachable ? "SSH only" : "unavailable")}`
  ].join("\n");
  item.show();
}

async function diagnose(
  output: vscode.OutputChannel,
  statusBar: vscode.StatusBarItem
): Promise<{ profile: WeaverSSHWorkspaceProfile; status: NebulaStatus; root: string }> {
  const { root, path: profilePath, profile } = await readWorkspaceProfile();
  const status = await readNebulaStatus(
    profile,
    configuredString("wvBinary", "wv"),
    configuredNumber("timeoutMs", 5000)
  );
  output.appendLine(`[weaverssh-nebula] profile: ${profilePath}`);
  output.appendLine(formatNebulaStatus(profile, status));
  for (const check of status.checks) {
    output.appendLine(`- ${check.name}: ${check.ok ? "ok" : "not-ok"}${check.detail ? ` (${check.detail})` : ""}`);
  }
  updateStatusBar(statusBar, profile, status);
  output.show(true);
  return { profile, status, root };
}

async function refreshAuthenticatedStatus(
  output: vscode.OutputChannel,
  statusBar: vscode.StatusBarItem,
  profile: WeaverSSHWorkspaceProfile,
  network: NebulaStatus
): Promise<SessionRuntimeStatus> {
  const runtime = await readSessionStatus(
    configuredString("wvBinary", "wv"),
    profile.target_node,
    configuredNumber("timeoutMs", 5000)
  );
  updateStatusBar(statusBar, profile, network, runtime);
  output.appendLine(`[weaverssh-nebula] authenticated target: ${runtime.targetNode.id}`);
  output.appendLine(`[weaverssh-nebula] binding: ${runtime.snapshot.binding}`);
  output.appendLine(`[weaverssh-nebula] route: ${runtime.routeLabel}`);
  return runtime;
}

export function registerNebulaCommands(context: vscode.ExtensionContext): void {
  const output = vscode.window.createOutputChannel("WeaverSSH Nebula");
  const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBar.name = "WeaverSSH Nebula Session";
  statusBar.command = "weaversshNebula.refreshSessionStatus";
  statusBar.text = "$(remote) WeaverSSH Nebula";
  statusBar.tooltip = "Refresh WeaverSSH SSH-over-Nebula session status";
  statusBar.show();
  context.subscriptions.push(output, statusBar);

  context.subscriptions.push(vscode.commands.registerCommand("weaversshNebula.diagnose", async () => {
    try {
      const { profile, status } = await diagnose(output, statusBar);
      const message = status.ssh_reachable
        ? `SSH over Nebula is reachable for ${profile.target_node}.`
        : `SSH over Nebula is unavailable for ${profile.target_node}.`;
      void vscode.window.showInformationMessage(message);
    } catch (error) {
      void vscode.window.showErrorMessage(`WeaverSSH Nebula diagnostics failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }));

  context.subscriptions.push(vscode.commands.registerCommand("weaversshNebula.refreshSessionStatus", async () => {
    try {
      const { profile, status } = await diagnose(output, statusBar);
      if (!status.ssh_reachable) {
        throw new Error("SSH protocol banner is not reachable over the configured route");
      }
      const runtime = await refreshAuthenticatedStatus(output, statusBar, profile, status);
      void vscode.window.showInformationMessage(
        `WeaverSSH session authenticated for ${runtime.targetNode.id}; route ${runtime.routeLabel}.`
      );
    } catch (error) {
      void vscode.window.showWarningMessage(`WeaverSSH session is not ready: ${error instanceof Error ? error.message : String(error)}`);
    }
  }));

  context.subscriptions.push(vscode.commands.registerCommand("weaversshNebula.connect", async () => {
    try {
      const { profile, status, root } = await diagnose(output, statusBar);
      if (!status.ssh_reachable) {
        throw new Error("SSH protocol banner was not reachable over the configured Nebula address");
      }
      if (!profile.session_host) {
        throw new Error("profile is diagnostic-only; add session_host.node_context and session_host.public_key_file to launch WeaverSSH");
      }
      const launch = profile.session_host;
      const localRoot = launch.local_root
        ? resolveWorkspacePath(root, launch.local_root)
        : root;
      const nodeContext = resolveWorkspacePath(root, launch.node_context);
      const publicKey = resolveWorkspacePath(root, launch.public_key_file);
      const wvBinary = configuredString("wvBinary", "wv");
      const sshArgs = launch.ssh_args && launch.ssh_args.length > 0 ? launch.ssh_args : ["-X"];
      const command = [
        wvBinary,
        "session-host",
        "--root", localRoot,
        "--node-context", nodeContext,
        "--public-key-file", publicKey,
        ...(launch.extra_args || []),
        "--",
        "ssh",
        ...sshArgs,
        profile.connection.ssh_host
      ].map(shellQuote).join(" ");

      const terminal = vscode.window.createTerminal({
        name: `WeaverSSH: ${profile.target_node}`,
        cwd: root
      });
      terminal.show();
      terminal.sendText(command, true);
      statusBar.text = `$(sync~spin) WeaverSSH: ${profile.target_node}`;
      statusBar.tooltip = "Waiting for the authenticated local WeaverSSH broker";

      let runtime: SessionRuntimeStatus;
      try {
        runtime = await waitForSession(
          wvBinary,
          profile.target_node,
          configuredNumber("sessionWaitTimeoutMs", 60000),
          configuredNumber("pollIntervalMs", 500)
        );
      } catch (error) {
        updateStatusBar(statusBar, profile, status);
        const detail = error instanceof Error ? error.message : String(error);
        output.appendLine(`[weaverssh-nebula] session launch continues, but readiness verification failed: ${detail}`);
        output.show(true);
        void vscode.window.showWarningMessage(
          `SSH was launched for ${profile.target_node}, but the authenticated WeaverSSH session is not ready: ${detail}`
        );
        return;
      }
      updateStatusBar(statusBar, profile, status, runtime);
      output.appendLine(`[weaverssh-nebula] session authenticated for ${runtime.targetNode.id}`);
      output.appendLine(`[weaverssh-nebula] route: ${runtime.routeLabel}`);
      output.show(true);
      void vscode.window.showInformationMessage(
        `WeaverSSH connected to ${runtime.targetNode.id}; authenticated route ${runtime.routeLabel}.`
      );
    } catch (error) {
      void vscode.window.showErrorMessage(`WeaverSSH Nebula connect failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }));
}
