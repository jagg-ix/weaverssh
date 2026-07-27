import * as path from "path";
import * as vscode from "vscode";
import {
  SSHX11_UI_API_VERSION,
  assertUiActionName,
  describeFeaturePlugin,
  describeUiAction,
  discoverFeaturePlugins,
  listFeaturePlugins,
  listUiActions,
  resolveUiActionPlan,
  type SSHX11ApiCommandEvent,
  type SSHX11ExtensionApi,
  type SSHX11FeaturePluginDescriptor,
  type SSHX11FeaturePluginFilter,
  type SSHX11NamedCommand,
  type SSHX11ReverseSocksSmokeRequest,
  type SSHX11SettingsSnapshot,
  type SSHX11UiActionDescriptor,
  type SSHX11UiActionName,
  type SSHX11UiActionRequest,
  type SSHX11WidgetLocation
} from "./ui-api";

export type {
  SSHX11ApiCommandEvent,
  SSHX11ExtensionApi,
  SSHX11FeaturePluginDescriptor,
  SSHX11FeaturePluginFilter,
  SSHX11NamedCommand,
  SSHX11ReverseSocksSmokeRequest,
  SSHX11SettingsSnapshot,
  SSHX11UiActionDescriptor,
  SSHX11UiActionName,
  SSHX11UiActionRequest,
  SSHX11WidgetLocation
} from "./ui-api";

const TERMINAL_NAME = "SSHX11 Ops";
const OUTPUT_CHANNEL_NAME = "SSHX11 Ops";

let outputChannel: vscode.OutputChannel | undefined;
let configureStatusBarItem: vscode.StatusBarItem | undefined;
let commandEventEmitter: vscode.EventEmitter<SSHX11ApiCommandEvent> | undefined;

function shellQuote(value: string): string {
  if (value.length === 0) {
    return "''";
  }
  if (!/[^\w@%+=:,./-]/.test(value)) {
    return value;
  }
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function getWorkspaceRoot(): string | undefined {
  const folder = vscode.workspace.workspaceFolders?.[0];
  return folder?.uri.fsPath;
}

function expandHome(input: string): string {
  if (!input.startsWith("~/")) {
    return input;
  }
  const home = process.env.HOME || process.env.USERPROFILE;
  if (!home) {
    return input;
  }
  return path.join(home, input.slice(2));
}

function getConfig(): vscode.WorkspaceConfiguration {
  return vscode.workspace.getConfiguration("sshx11");
}

function getConfigurationTarget(): vscode.ConfigurationTarget {
  return vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0
    ? vscode.ConfigurationTarget.Workspace
    : vscode.ConfigurationTarget.Global;
}

async function updateSetting(name: string, value: unknown): Promise<void> {
  await getConfig().update(name, value, getConfigurationTarget());
}

function resolveOpsScriptPath(root: string): string {
  const configured = getSetting("opsScriptPath", "tools/verification/sshx11_ops.sh");
  const expanded = expandHome(configured);
  if (path.isAbsolute(expanded)) {
    return expanded;
  }
  return path.join(root, expanded);
}

function createOpsTerminal(root: string): vscode.Terminal {
  return vscode.window.createTerminal({
    name: TERMINAL_NAME,
    cwd: root
  });
}

function getSetting(name: string, fallback: string): string {
  const raw = getConfig().get<unknown>(name, fallback);
  return String(raw ?? fallback).trim();
}

function parseBool(value: unknown, fallback: boolean): boolean {
  if (typeof value === "boolean") {
    return value;
  }
  if (value === undefined || value === null) {
    return fallback;
  }
  const normalized = String(value).trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) {
    return true;
  }
  if (["0", "false", "no", "off"].includes(normalized)) {
    return false;
  }
  return fallback;
}

function getSettingBool(name: string, fallback: boolean): boolean {
  const raw = getConfig().get<unknown>(name, fallback);
  return parseBool(raw, fallback);
}

function getSettingInt(name: string, fallback: number): number {
  const raw = getConfig().get<unknown>(name, fallback);
  const parsed = Number.parseInt(String(raw ?? fallback).trim(), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

function getWidgetLocationSetting(): SSHX11WidgetLocation {
  const raw = getSetting("widgetLocation", "auto").toLowerCase();
  if (raw === "top" || raw === "bottom") {
    return raw;
  }
  return "auto";
}

function resolveWidgetLocation(): "bottom" | "top" {
  const location = getWidgetLocationSetting();
  if (location === "top") {
    return "top";
  }
  if (location === "bottom") {
    return "bottom";
  }
  // In VS Code, extension quick actions are most commonly placed in status bar.
  return "bottom";
}

function getSettingsSnapshot(): SSHX11SettingsSnapshot {
  const widgetLocation = getWidgetLocationSetting();
  const resolvedWidgetLocation = resolveWidgetLocation();
  return {
    opsScriptPath: getSetting("opsScriptPath", "tools/verification/sshx11_ops.sh"),
    showStatusBarConfigure: getSettingBool("showStatusBarConfigure", true),
    widgetLocation,
    resolvedWidgetLocation,
    verbose: getSettingBool("verbose", false),
    defaultRemoteHost: getSetting("defaultRemoteHost", ""),
    defaultRemoteUser: getSetting("defaultRemoteUser", "root"),
    defaultIdentityFile: getSetting("defaultIdentityFile", "~/.ssh/id_ed25519"),
    defaultSshConfigPath: getSetting("defaultSshConfigPath", ""),
    defaultSshProxyJump: getSetting("defaultSshProxyJump", ""),
    defaultSshProxyCommand: getSetting("defaultSshProxyCommand", ""),
    sshVerbosity: clamp(getSettingInt("sshVerbosity", 0), 0, 3),
    sshLogLevel: getSetting("sshLogLevel", ""),
    sshLogFile: getSetting("sshLogFile", ""),
    agentMode: getSetting("agentMode", "auto"),
    forwardAgent: getSettingBool("forwardAgent", false),
    identityAgent: getSetting("identityAgent", ""),
    sshClientAdapter: getSetting("sshClientAdapter", "auto"),
    virtualizationLayer: getSetting("virtualizationLayer", "auto"),
    setupKind: getSetting("setupKind", "auto"),
    organizationProvider: getSetting("organizationProvider", "none"),
    chainConnector: getSetting("chainConnector", "none"),
    organizationConfigPath: getSetting("organizationConfigPath", ""),
    remotePlatform: getSetting("remotePlatform", "auto"),
    remoteShellBin: getSetting("remoteShellBin", "sh"),
    remoteShellLogin: getSettingBool("remoteShellLogin", true),
    remotePythonBin: getSetting("remotePythonBin", ""),
    insecureHostKey: getSettingBool("insecureHostKey", false)
  };
}


async function runOpsCommand(subcommand: string, args: string[] = []): Promise<void> {
  const root = getWorkspaceRoot();
  if (!root) {
    void vscode.window.showErrorMessage("SSHX11 extension needs an opened workspace folder.");
    return;
  }

  const script = resolveOpsScriptPath(root);
  const renderedArgs = args.map((arg) => shellQuote(arg)).join(" ");
  const cmd = `${shellQuote(script)} ${subcommand}${renderedArgs ? ` ${renderedArgs}` : ""}`;

  if (outputChannel) {
    outputChannel.appendLine(`[sshx11] ${cmd}`);
  }
  if (getSettingBool("verbose", false)) {
    void vscode.window.showInformationMessage(`SSHX11 command: ${subcommand}`);
  }

  const terminal = createOpsTerminal(root);
  terminal.show();
  terminal.sendText(cmd, true);
  commandEventEmitter?.fire({
    subcommand,
    args: [...args],
    issuedAtUnixMs: Date.now()
  });
}

function refreshConfigureStatusBarVisibility(): void {
  const showWidget = getSettingBool("showStatusBarConfigure", true);
  const resolvedLocation = resolveWidgetLocation();
  const showTop = showWidget && resolvedLocation === "top";
  const showBottom = showWidget && resolvedLocation === "bottom";

  void vscode.commands.executeCommand("setContext", "sshx11WidgetTop", showTop);
  void vscode.commands.executeCommand("setContext", "sshx11WidgetBottom", showBottom);

  if (!configureStatusBarItem) {
    return;
  }
  if (showBottom) {
    configureStatusBarItem.show();
  } else {
    configureStatusBarItem.hide();
  }
}

function formatOnOff(value: boolean): string {
  return value ? "on" : "off";
}

interface ConfigureActionPick extends vscode.QuickPickItem {
  run: () => Promise<void>;
}

async function configureStringSetting(
  setting: string,
  title: string,
  prompt: string,
  currentValue: string,
  placeholder = ""
): Promise<void> {
  const next = await vscode.window.showInputBox({
    title,
    prompt,
    value: currentValue,
    placeHolder: placeholder,
    ignoreFocusOut: true
  });
  if (next === undefined) {
    return;
  }
  await updateSetting(setting, next.trim());
}

async function configureQuickPickSetting(
  title: string,
  placeHolder: string,
  options: Array<{ label: string; value: string | number }>,
  setting: string
): Promise<void> {
  const choice = await vscode.window.showQuickPick(options, {
    title,
    placeHolder,
    ignoreFocusOut: true
  });
  if (!choice) {
    return;
  }
  await updateSetting(setting, choice.value);
}

function buildConfigurePicks(): ConfigureActionPick[] {
  const widgetLocation = getWidgetLocationSetting();
  const resolvedWidgetLocation = resolveWidgetLocation();
  const verbose = getSettingBool("verbose", false);
  const showStatusBarConfigure = getSettingBool("showStatusBarConfigure", true);
  const insecureHostKey = getSettingBool("insecureHostKey", false);
  const forwardAgent = getSettingBool("forwardAgent", false);
  const remoteShellLogin = getSettingBool("remoteShellLogin", true);

  return [
    {
      label: "Open SSHX11 Settings",
      description: "Open full VS Code settings view",
      run: async () => {
        await vscode.commands.executeCommand("workbench.action.openSettings", "sshx11.");
      }
    },
    {
      label: `Toggle Status Bar Widget (${formatOnOff(showStatusBarConfigure)})`,
      description: "Show/hide status bar Configure button",
      run: async () => {
        await updateSetting("showStatusBarConfigure", !showStatusBarConfigure);
        refreshConfigureStatusBarVisibility();
      }
    },
    {
      label: `Set widget location (${widgetLocation} -> ${resolvedWidgetLocation})`,
      description: "auto uses the most common placement (bottom status bar)",
      run: async () => {
        await configureQuickPickSetting(
          "SSHX11 Widget Location",
          "Choose where the Configure widget should appear",
          [
            { label: "auto (recommended: bottom status bar)", value: "auto" },
            { label: "bottom (status bar)", value: "bottom" },
            { label: "top (window frame actions)", value: "top" }
          ],
          "widgetLocation"
        );
        refreshConfigureStatusBarVisibility();
      }
    },
    {
      label: `Toggle Extension Verbose Output (${formatOnOff(verbose)})`,
      description: "Show command notifications and richer output traces",
      run: async () => {
        await updateSetting("verbose", !verbose);
      }
    },
    {
      label: `Set ops script path (${getSetting("opsScriptPath", "tools/verification/sshx11_ops.sh") || "unset"})`,
      description: "Path to sshx11_ops.sh",
      run: async () =>
        configureStringSetting(
          "opsScriptPath",
          "SSHX11 Ops Script Path",
          "Path to sshx11_ops.sh (absolute or workspace-relative)",
          getSetting("opsScriptPath", "tools/verification/sshx11_ops.sh")
        )
    },
    {
      label: `Set default remote host (${getSetting("defaultRemoteHost", "") || "unset"})`,
      description: "Host used by Reverse SOCKS smoke",
      run: async () =>
        configureStringSetting(
          "defaultRemoteHost",
          "Default Remote Host",
          "Remote host for SSHX11 smoke runs",
          getSetting("defaultRemoteHost", "")
        )
    },
    {
      label: `Set default remote user (${getSetting("defaultRemoteUser", "root")})`,
      description: "SSH username used by Reverse SOCKS smoke",
      run: async () =>
        configureStringSetting(
          "defaultRemoteUser",
          "Default Remote User",
          "Remote user for SSHX11 smoke runs",
          getSetting("defaultRemoteUser", "root")
        )
    },
    {
      label: `Set identity file (${getSetting("defaultIdentityFile", "") || "unset"})`,
      description: "SSH key path passed to smoke/verify",
      run: async () =>
        configureStringSetting(
          "defaultIdentityFile",
          "Default Identity File",
          "SSH key file path",
          getSetting("defaultIdentityFile", "~/.ssh/id_ed25519")
        )
    },
    {
      label: `Toggle insecure host key (${formatOnOff(insecureHostKey)})`,
      description: "StrictHostKeyChecking=no (development-only)",
      run: async () => {
        await updateSetting("insecureHostKey", !insecureHostKey);
      }
    },
    {
      label: `Set SSH config path (${getSetting("defaultSshConfigPath", "") || "unset"})`,
      description: "OpenSSH config file (-F)",
      run: async () =>
        configureStringSetting(
          "defaultSshConfigPath",
          "SSH Config Path",
          "Optional OpenSSH config file path",
          getSetting("defaultSshConfigPath", "")
        )
    },
    {
      label: `Set ProxyJump (${getSetting("defaultSshProxyJump", "") || "unset"})`,
      description: "SSH -o ProxyJump",
      run: async () =>
        configureStringSetting(
          "defaultSshProxyJump",
          "SSH ProxyJump",
          "Optional SSH ProxyJump",
          getSetting("defaultSshProxyJump", "")
        )
    },
    {
      label: `Set ProxyCommand (${getSetting("defaultSshProxyCommand", "") || "unset"})`,
      description: "SSH -o ProxyCommand",
      run: async () =>
        configureStringSetting(
          "defaultSshProxyCommand",
          "SSH ProxyCommand",
          "Optional SSH ProxyCommand",
          getSetting("defaultSshProxyCommand", "")
        )
    },
    {
      label: `Set agent mode (${getSetting("agentMode", "auto")})`,
      description: "auto / require / disable",
      run: async () =>
        configureQuickPickSetting(
          "SSH Agent Mode",
          "Select agent transport policy",
          [
            { label: "auto", value: "auto" },
            { label: "require", value: "require" },
            { label: "disable", value: "disable" }
          ],
          "agentMode"
        )
    },
    {
      label: `Toggle forward agent (${formatOnOff(forwardAgent)})`,
      description: "Enable SSH agent forwarding (-A)",
      run: async () => {
        await updateSetting("forwardAgent", !forwardAgent);
      }
    },
    {
      label: `Set identity agent (${getSetting("identityAgent", "") || "unset"})`,
      description: "IdentityAgent socket/path (supports env:VAR/pageant:)",
      run: async () =>
        configureStringSetting(
          "identityAgent",
          "Identity Agent",
          "IdentityAgent socket/path (env:VAR and pageant: supported)",
          getSetting("identityAgent", "")
        )
    },
    {
      label: `Set SSH verbosity (${clamp(getSettingInt("sshVerbosity", 0), 0, 3)})`,
      description: "0..3 mapped to -v/-vv/-vvv",
      run: async () =>
        configureQuickPickSetting(
          "SSH Verbosity",
          "Select verbose flag count",
          [
            { label: "0 (off)", value: 0 },
            { label: "1 (-v)", value: 1 },
            { label: "2 (-vv)", value: 2 },
            { label: "3 (-vvv)", value: 3 }
          ],
          "sshVerbosity"
        )
    },
    {
      label: `Set SSH log level (${getSetting("sshLogLevel", "") || "unset"})`,
      description: "LogLevel (INFO/VERBOSE/DEBUG3)",
      run: async () =>
        configureQuickPickSetting(
          "SSH LogLevel",
          "Select OpenSSH LogLevel",
          [
            { label: "unset", value: "" },
            { label: "QUIET", value: "QUIET" },
            { label: "FATAL", value: "FATAL" },
            { label: "ERROR", value: "ERROR" },
            { label: "INFO", value: "INFO" },
            { label: "VERBOSE", value: "VERBOSE" },
            { label: "DEBUG", value: "DEBUG" },
            { label: "DEBUG1", value: "DEBUG1" },
            { label: "DEBUG2", value: "DEBUG2" },
            { label: "DEBUG3", value: "DEBUG3" }
          ],
          "sshLogLevel"
        )
    },
    {
      label: `Set SSH log file (${getSetting("sshLogFile", "") || "unset"})`,
      description: "OpenSSH -E <file>",
      run: async () =>
        configureStringSetting(
          "sshLogFile",
          "SSH Log File",
          "Local path for SSH client logs (-E)",
          getSetting("sshLogFile", "")
        )
    },
    {
      label: `Set remote platform (${getSetting("remotePlatform", "auto")})`,
      description: "auto / linux-* / macos / freebsd-* / openbsd / legacy unix",
      run: async () =>
        configureQuickPickSetting(
          "Remote Platform",
          "Select remote compatibility profile",
          [
            { label: "auto", value: "auto" },
            { label: "linux (legacy alias)", value: "linux" },
            { label: "linux-generic", value: "linux-generic" },
            { label: "linux-headless", value: "linux-headless" },
            { label: "linux-gui", value: "linux-gui" },
            { label: "macos", value: "macos" },
            { label: "freebsd", value: "freebsd" },
            { label: "freebsd-generic", value: "freebsd-generic" },
            { label: "freebsd-gui", value: "freebsd-gui" },
            { label: "openbsd", value: "openbsd" },
            { label: "aix", value: "aix" },
            { label: "solaris", value: "solaris" },
            { label: "zos", value: "zos" },
            { label: "generic", value: "generic" }
          ],
          "remotePlatform"
        )
    },
    {
      label: `Set remote shell (${getSetting("remoteShellBin", "sh")})`,
      description: "Remote shell binary for probe execution",
      run: async () =>
        configureStringSetting(
          "remoteShellBin",
          "Remote Shell",
          "Remote shell binary (e.g. sh, ksh, /bin/ksh)",
          getSetting("remoteShellBin", "sh")
        )
    },
    {
      label: `Toggle remote shell login mode (${formatOnOff(remoteShellLogin)})`,
      description: "Use -lc vs -c for remote probe shell",
      run: async () => {
        await updateSetting("remoteShellLogin", !remoteShellLogin);
      }
    },
    {
      label: `Set remote python (${getSetting("remotePythonBin", "") || "unset"})`,
      description: "Preferred remote Python executable",
      run: async () =>
        configureStringSetting(
          "remotePythonBin",
          "Remote Python",
          "Preferred remote python executable path",
          getSetting("remotePythonBin", "")
        )
    }
  ];
}

async function showConfigurePopup(): Promise<void> {
  while (true) {
    const selected = await vscode.window.showQuickPick(buildConfigurePicks(), {
      title: "SSHX11 Configure",
      placeHolder: "Select an option to update (Esc to close)",
      ignoreFocusOut: true
    });
    if (!selected) {
      return;
    }
    try {
      await selected.run();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      void vscode.window.showErrorMessage(`SSHX11 configure failed: ${message}`);
    }
  }
}

async function runReverseSocksSmoke(request?: SSHX11ReverseSocksSmokeRequest): Promise<void> {
  const hostDefault = getSetting("defaultRemoteHost", "");
  const userDefault = getSetting("defaultRemoteUser", "root");
  const keyDefault = getSetting("defaultIdentityFile", "~/.ssh/id_ed25519");
  const requestHost = String(request?.host ?? "").trim();
  const requestUser = String(request?.user ?? "").trim();
  const requestIdentityFile = String(request?.identityFile ?? "").trim();

  const host = requestHost
    || (await vscode.window.showInputBox({
      title: "SSHX11 Reverse SOCKS Smoke",
      prompt: "Remote host",
      value: hostDefault,
      ignoreFocusOut: true
    }))?.trim();
  if (!host) {
    return;
  }

  const user = requestUser
    || (await vscode.window.showInputBox({
      title: "SSHX11 Reverse SOCKS Smoke",
      prompt: "Remote user",
      value: userDefault,
      ignoreFocusOut: true
    }))?.trim();
  if (!user) {
    return;
  }

  const key = requestIdentityFile
    || (await vscode.window.showInputBox({
      title: "SSHX11 Reverse SOCKS Smoke",
      prompt: "Identity file (optional)",
      value: keyDefault,
      ignoreFocusOut: true
    }))?.trim();

  const plan = resolveUiActionPlan("reverseSocksSmoke", getSettingsSnapshot(), {
    host,
    user,
    identityFile: key || ""
  });
  if (plan.kind !== "ops-command") {
    return;
  }

  await runOpsCommand(plan.subcommand, plan.args);
}

async function openWorkspaceDocument(relativePath: string): Promise<void> {
  const root = getWorkspaceRoot();
  if (!root) {
    void vscode.window.showErrorMessage("SSHX11 extension needs an opened workspace folder.");
    return;
  }
  const docPath = path.join(root, relativePath);
  const doc = await vscode.workspace.openTextDocument(docPath);
  await vscode.window.showTextDocument(doc, { preview: false });
}

async function runUiAction(name: SSHX11UiActionName, request?: SSHX11UiActionRequest): Promise<void> {
  const actionName = assertUiActionName(String(name || "").trim());
  const plan = resolveUiActionPlan(actionName, getSettingsSnapshot(), request || {});

  if (plan.kind === "configuration") {
    await showConfigurePopup();
    return;
  }
  if (plan.kind === "ops-command") {
    await runOpsCommand(plan.subcommand, plan.args);
    return;
  }
  if (plan.kind === "prompted-ops-command") {
    await runReverseSocksSmoke(request);
    return;
  }
  if (plan.kind === "document") {
    await openWorkspaceDocument(plan.relativePath);
    return;
  }
}

async function runNamedCommand(name: SSHX11NamedCommand, request?: SSHX11ReverseSocksSmokeRequest): Promise<void> {
  await runUiAction(name, request);
}

export function activate(context: vscode.ExtensionContext): SSHX11ExtensionApi {
  outputChannel = vscode.window.createOutputChannel(OUTPUT_CHANNEL_NAME);
  context.subscriptions.push(outputChannel);
  commandEventEmitter = new vscode.EventEmitter<SSHX11ApiCommandEvent>();
  context.subscriptions.push(commandEventEmitter);

  configureStatusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 1000);
  configureStatusBarItem.name = "SSHX11 Configure";
  configureStatusBarItem.command = "sshx11.configure";
  configureStatusBarItem.text = "$(settings-gear) SSHX11";
  configureStatusBarItem.tooltip = "Open SSHX11 configure popup";
  context.subscriptions.push(configureStatusBarItem);
  refreshConfigureStatusBarVisibility();

  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (
        event.affectsConfiguration("sshx11.showStatusBarConfigure")
        || event.affectsConfiguration("sshx11.widgetLocation")
      ) {
        refreshConfigureStatusBarVisibility();
      }
    })
  );

  const register = (command: string, callback: () => Promise<void>): void => {
    context.subscriptions.push(vscode.commands.registerCommand(command, callback));
  };

  register("sshx11.configure", async () => runNamedCommand("configure"));
  register("sshx11.startServices", async () => runNamedCommand("startServices"));
  register("sshx11.stopServices", async () => runNamedCommand("stopServices"));
  register("sshx11.statusLocal", async () => runNamedCommand("statusLocal"));
  register("sshx11.socksFallbackStart", async () => runNamedCommand("socksFallbackStart"));
  register("sshx11.vscodeProfileGen", async () => runNamedCommand("vscodeProfileGen"));
  register("sshx11.verifyExtensionHosts", async () => runNamedCommand("verifyExtensionHosts"));
  register("sshx11.reverseSocksSmoke", async () => runNamedCommand("reverseSocksSmoke"));
  register("sshx11.webdavStart", async () => runNamedCommand("webdavStart"));
  register("sshx11.ninepStart", async () => runNamedCommand("ninepStart"));
  register("sshx11.ninepStatus", async () => runNamedCommand("ninepStatus"));
  register("sshx11.ninepStop", async () => runNamedCommand("ninepStop"));
  register("sshx11.ninepPlan", async () => runNamedCommand("ninepPlan"));
  register("sshx11.openWorkflowsDoc", async () => runNamedCommand("openWorkflowsDoc"));

  context.subscriptions.push(
    vscode.commands.registerCommand("sshx11.api.getSettingsSnapshot", async (): Promise<SSHX11SettingsSnapshot> =>
      getSettingsSnapshot()
    )
  );
  context.subscriptions.push(
    vscode.commands.registerCommand(
      "sshx11.api.runOpsCommand",
      async (subcommand: string, args: string[] = []): Promise<void> => {
        const resolvedSubcommand = String(subcommand || "").trim();
        if (!resolvedSubcommand) {
          throw new Error("sshx11.api.runOpsCommand requires a non-empty subcommand");
        }
        await runOpsCommand(
          resolvedSubcommand,
          Array.isArray(args) ? args.map((item) => String(item)) : []
        );
      }
    )
  );
  context.subscriptions.push(
    vscode.commands.registerCommand(
      "sshx11.api.runNamedCommand",
      async (name: SSHX11NamedCommand, request?: SSHX11ReverseSocksSmokeRequest): Promise<void> =>
        runNamedCommand(name, request)
    )
  );
  context.subscriptions.push(
    vscode.commands.registerCommand("sshx11.api.showConfigure", async (): Promise<void> => showConfigurePopup())
  );
  context.subscriptions.push(
    vscode.commands.registerCommand("sshx11.api.listUiActions", async (): Promise<SSHX11UiActionDescriptor[]> =>
      listUiActions()
    )
  );
  context.subscriptions.push(
    vscode.commands.registerCommand(
      "sshx11.api.describeUiAction",
      async (name: SSHX11UiActionName): Promise<SSHX11UiActionDescriptor | undefined> =>
        describeUiAction(assertUiActionName(String(name || "").trim()))
    )
  );
  context.subscriptions.push(
    vscode.commands.registerCommand(
      "sshx11.api.runUiAction",
      async (name: SSHX11UiActionName, request?: SSHX11UiActionRequest): Promise<void> =>
        runUiAction(name, request)
    )
  );
  context.subscriptions.push(
    vscode.commands.registerCommand(
      "sshx11.api.listFeaturePlugins",
      async (filter?: SSHX11FeaturePluginFilter): Promise<SSHX11FeaturePluginDescriptor[]> =>
        listFeaturePlugins(filter || {})
    )
  );
  context.subscriptions.push(
    vscode.commands.registerCommand(
      "sshx11.api.discoverFeaturePlugins",
      async (filter?: SSHX11FeaturePluginFilter): Promise<SSHX11FeaturePluginDescriptor[]> =>
        discoverFeaturePlugins(filter || {})
    )
  );
  context.subscriptions.push(
    vscode.commands.registerCommand(
      "sshx11.api.describeFeaturePlugin",
      async (id: string): Promise<SSHX11FeaturePluginDescriptor | undefined> =>
        describeFeaturePlugin(String(id || "").trim())
    )
  );

  return {
    version: SSHX11_UI_API_VERSION,
    onDidRunCommand: commandEventEmitter.event,
    showConfigure: showConfigurePopup,
    runOpsCommand: async (subcommand: string, args: string[] = []): Promise<void> =>
      runOpsCommand(subcommand, args),
    runNamedCommand: async (name: SSHX11NamedCommand, request?: SSHX11ReverseSocksSmokeRequest): Promise<void> =>
      runNamedCommand(name, request),
    runReverseSocksSmoke: async (request?: SSHX11ReverseSocksSmokeRequest): Promise<void> =>
      runReverseSocksSmoke(request),
    getSettingsSnapshot: () => getSettingsSnapshot(),
    listUiActions: () => listUiActions(),
    describeUiAction: (name: SSHX11UiActionName): SSHX11UiActionDescriptor | undefined => describeUiAction(name),
    runUiAction: async (name: SSHX11UiActionName, request?: SSHX11UiActionRequest): Promise<void> =>
      runUiAction(name, request),
    listFeaturePlugins: (filter: SSHX11FeaturePluginFilter = {}): SSHX11FeaturePluginDescriptor[] =>
      listFeaturePlugins(filter),
    discoverFeaturePlugins: (filter: SSHX11FeaturePluginFilter = {}): SSHX11FeaturePluginDescriptor[] =>
      discoverFeaturePlugins(filter),
    describeFeaturePlugin: (id: string): SSHX11FeaturePluginDescriptor | undefined =>
      describeFeaturePlugin(id)
  };
}

export function deactivate(): void {
  // no-op
}
