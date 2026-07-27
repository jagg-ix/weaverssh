import * as vscode from "vscode";

type SSHX11NamedCommand =
  | "configure"
  | "startServices"
  | "stopServices"
  | "statusLocal"
  | "socksFallbackStart"
  | "vscodeProfileGen"
  | "verifyExtensionHosts"
  | "reverseSocksSmoke"
  | "webdavStart"
  | "openWorkflowsDoc";

type SSHX11UiActionName = SSHX11NamedCommand;

interface SSHX11UiActionDescriptor {
  name: SSHX11UiActionName;
  commandId: string;
  title: string;
  category: string;
  kind: string;
  description: string;
  subcommand?: string;
}

interface SSHX11SettingsSnapshot {
  remotePlatform: string;
  sshClientAdapter: string;
  virtualizationLayer: string;
  setupKind: string;
  organizationProvider: string;
  chainConnector: string;
  defaultRemoteHost: string;
}

interface SSHX11ExtensionApi {
  readonly version: string;
  runNamedCommand(name: SSHX11NamedCommand): Promise<void>;
  runOpsCommand(subcommand: string, args?: string[]): Promise<void>;
  getSettingsSnapshot(): SSHX11SettingsSnapshot;
  listUiActions(): SSHX11UiActionDescriptor[];
  describeUiAction(name: SSHX11UiActionName): SSHX11UiActionDescriptor | undefined;
  runUiAction(name: SSHX11UiActionName, request?: Record<string, string>): Promise<void>;
}

export function activate(context: vscode.ExtensionContext): void {
  const disposable = vscode.commands.registerCommand("sampleSshx11Consumer.run", async () => {
    const provider = vscode.extensions.getExtension<SSHX11ExtensionApi>("local.vscode-sshx11");
    if (!provider) {
      void vscode.window.showErrorMessage("SSHX11 provider extension not found: local.vscode-sshx11");
      return;
    }

    const api = await provider.activate();
    const snapshot = api.getSettingsSnapshot();

    // End-to-end usage: discover UI actions, inspect one, then execute through the same path the UI uses.
    const actions = api.listUiActions();
    const statusAction = api.describeUiAction("statusLocal");
    await api.runUiAction("statusLocal");
    await api.runNamedCommand("verifyExtensionHosts");
    await api.runOpsCommand("status-local");
    await vscode.commands.executeCommand("sshx11.api.runUiAction", "webdavStart");

    void vscode.window.showInformationMessage(
      `SSHX11 API OK (v${api.version}) actions=${actions.length} status=${statusAction?.kind || "missing"} platform=${snapshot.remotePlatform || "auto"} sshAdapter=${snapshot.sshClientAdapter || "auto"} virtualization=${snapshot.virtualizationLayer || "auto"} setup=${snapshot.setupKind || "auto"} provider=${snapshot.organizationProvider || "none"} connector=${snapshot.chainConnector || "none"} host=${snapshot.defaultRemoteHost || "unset"}`
    );
  });

  context.subscriptions.push(disposable);
}

export function deactivate(): void {
  // no-op sample
}
