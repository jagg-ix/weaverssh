import type * as vscode from "vscode";

export const SSHX11_UI_API_VERSION = "0.0.1";

export interface SSHX11ReverseSocksSmokeRequest {
  host?: string;
  user?: string;
  identityFile?: string;
}

export type SSHX11WidgetLocation = "auto" | "bottom" | "top";

export type SSHX11NamedCommand =
  | "configure"
  | "startServices"
  | "stopServices"
  | "statusLocal"
  | "socksFallbackStart"
  | "vscodeProfileGen"
  | "verifyExtensionHosts"
  | "reverseSocksSmoke"
  | "webdavStart"
  | "ninepStart"
  | "ninepStatus"
  | "ninepStop"
  | "ninepPlan"
  | "openWorkflowsDoc";

export type SSHX11UiActionName = SSHX11NamedCommand;

export interface SSHX11ApiCommandEvent {
  subcommand: string;
  args: string[];
  issuedAtUnixMs: number;
}

export interface SSHX11SettingsSnapshot {
  opsScriptPath: string;
  showStatusBarConfigure: boolean;
  widgetLocation: SSHX11WidgetLocation;
  resolvedWidgetLocation: "bottom" | "top";
  verbose: boolean;
  defaultRemoteHost: string;
  defaultRemoteUser: string;
  defaultIdentityFile: string;
  defaultSshConfigPath: string;
  defaultSshProxyJump: string;
  defaultSshProxyCommand: string;
  sshVerbosity: number;
  sshLogLevel: string;
  sshLogFile: string;
  agentMode: string;
  forwardAgent: boolean;
  identityAgent: string;
  sshClientAdapter: string;
  virtualizationLayer: string;
  setupKind: string;
  organizationProvider: string;
  chainConnector: string;
  organizationConfigPath: string;
  remotePlatform: string;
  remoteShellBin: string;
  remoteShellLogin: boolean;
  remotePythonBin: string;
  insecureHostKey: boolean;
}

export interface SSHX11UiActionDescriptor {
  readonly name: SSHX11UiActionName;
  readonly commandId: string;
  readonly title: string;
  readonly category: "configuration" | "lifecycle" | "workflow" | "documentation";
  readonly kind: "configuration" | "ops-command" | "prompted-ops-command" | "document";
  readonly description: string;
  readonly subcommand?: string;
}

export type SSHX11UiActionRequest = SSHX11ReverseSocksSmokeRequest;

export type SSHX11UiActionPlan =
  | {
      readonly ok: true;
      readonly name: SSHX11UiActionName;
      readonly kind: "configuration";
      readonly action: "showConfigure";
    }
  | {
      readonly ok: true;
      readonly name: SSHX11UiActionName;
      readonly kind: "ops-command";
      readonly subcommand: string;
      readonly args: string[];
    }
  | {
      readonly ok: true;
      readonly name: SSHX11UiActionName;
      readonly kind: "prompted-ops-command";
      readonly subcommand: "reverse-socks-smoke";
      readonly defaults: SSHX11ReverseSocksSmokeRequest;
      readonly missing: Array<"host" | "user">;
    }
  | {
      readonly ok: true;
      readonly name: SSHX11UiActionName;
      readonly kind: "document";
      readonly relativePath: string;
    };

export interface SSHX11FeaturePluginCommandDescriptor {
  readonly id: string;
  readonly opsSubcommand: string;
  readonly description: string;
  readonly available: boolean;
}

export interface SSHX11FeaturePluginServiceDescriptor {
  readonly id: string;
  readonly binary: string;
  readonly protocols: string[];
  readonly defaultListen: string;
  readonly runtimes: string[];
  readonly readOnly: boolean;
}

export interface SSHX11FeaturePluginDescriptor {
  readonly id: string;
  readonly name: string;
  readonly kind: "service" | "feature" | string;
  readonly enabledByDefault: boolean;
  readonly available: boolean;
  readonly description: string;
  readonly provides: string[];
  readonly services: SSHX11FeaturePluginServiceDescriptor[];
  readonly commands: SSHX11FeaturePluginCommandDescriptor[];
  readonly docs: string[];
  readonly tags: string[];
  readonly missingArtifacts: string[];
  readonly missingCommands: string[];
}

export interface SSHX11FeaturePluginFilter {
  readonly kind?: string;
  readonly feature?: string;
  readonly tag?: string;
  readonly enabledOnly?: boolean;
}

export interface SSHX11ExtensionApi {
  readonly version: string;
  readonly onDidRunCommand: vscode.Event<SSHX11ApiCommandEvent>;
  showConfigure(): Promise<void>;
  runOpsCommand(subcommand: string, args?: string[]): Promise<void>;
  runNamedCommand(name: SSHX11NamedCommand, request?: SSHX11ReverseSocksSmokeRequest): Promise<void>;
  runReverseSocksSmoke(request?: SSHX11ReverseSocksSmokeRequest): Promise<void>;
  getSettingsSnapshot(): SSHX11SettingsSnapshot;
  listUiActions(): SSHX11UiActionDescriptor[];
  describeUiAction(name: SSHX11UiActionName): SSHX11UiActionDescriptor | undefined;
  runUiAction(name: SSHX11UiActionName, request?: SSHX11UiActionRequest): Promise<void>;
  listFeaturePlugins(filter?: SSHX11FeaturePluginFilter): SSHX11FeaturePluginDescriptor[];
  discoverFeaturePlugins(filter?: SSHX11FeaturePluginFilter): SSHX11FeaturePluginDescriptor[];
  describeFeaturePlugin(id: string): SSHX11FeaturePluginDescriptor | undefined;
}

export const SSHX11_UI_ACTIONS: readonly SSHX11UiActionDescriptor[] = Object.freeze([
  {
    name: "configure",
    commandId: "sshx11.configure",
    title: "SSHX11: Configure",
    category: "configuration",
    kind: "configuration",
    description: "Open the Configure popup and update SSHX11 extension settings."
  },
  {
    name: "startServices",
    commandId: "sshx11.startServices",
    title: "SSHX11: Start Services",
    category: "lifecycle",
    kind: "ops-command",
    subcommand: "service-start",
    description: "Start local SSHX11 control/data-plane services."
  },
  {
    name: "stopServices",
    commandId: "sshx11.stopServices",
    title: "SSHX11: Stop Services",
    category: "lifecycle",
    kind: "ops-command",
    subcommand: "service-stop",
    description: "Stop local SSHX11 control/data-plane services."
  },
  {
    name: "statusLocal",
    commandId: "sshx11.statusLocal",
    title: "SSHX11: Status (Local)",
    category: "lifecycle",
    kind: "ops-command",
    subcommand: "status-local",
    description: "Inspect local service, policy, and state health."
  },
  {
    name: "socksFallbackStart",
    commandId: "sshx11.socksFallbackStart",
    title: "SSHX11: Start SOCKS Fallback",
    category: "workflow",
    kind: "ops-command",
    subcommand: "socks-fallback-start",
    description: "Start the local SOCKS fallback path when direct routing is unavailable."
  },
  {
    name: "vscodeProfileGen",
    commandId: "sshx11.vscodeProfileGen",
    title: "SSHX11: Generate VS Code Profiles",
    category: "workflow",
    kind: "ops-command",
    subcommand: "vscode-profile-gen",
    description: "Generate local, remote, and reverse-SOCKS VS Code profile artifacts."
  },
  {
    name: "verifyExtensionHosts",
    commandId: "sshx11.verifyExtensionHosts",
    title: "SSHX11: Verify Extension Hosts",
    category: "workflow",
    kind: "ops-command",
    subcommand: "verify-extension-hosts",
    description: "Validate extension-host profile and SSH adapter compatibility settings."
  },
  {
    name: "reverseSocksSmoke",
    commandId: "sshx11.reverseSocksSmoke",
    title: "SSHX11: Reverse SOCKS Smoke",
    category: "workflow",
    kind: "prompted-ops-command",
    subcommand: "reverse-socks-smoke",
    description: "Run the prompted or programmatic reverse-SOCKS smoke workflow."
  },
  {
    name: "webdavStart",
    commandId: "sshx11.webdavStart",
    title: "SSHX11: Start WebDAV",
    category: "workflow",
    kind: "ops-command",
    subcommand: "webdav-start",
    description: "Start the local lightweight WebDAV endpoint."
  },
  {
    name: "ninepStart",
    commandId: "sshx11.ninepStart",
    title: "SSHX11: Start 9P Service",
    category: "workflow",
    kind: "ops-command",
    subcommand: "9p-start",
    description: "Start the repo-native read-only wv-9p service for VFS workflows."
  },
  {
    name: "ninepStatus",
    commandId: "sshx11.ninepStatus",
    title: "SSHX11: 9P Service Status",
    category: "workflow",
    kind: "ops-command",
    subcommand: "9p-status",
    description: "Inspect the repo-native wv-9p service status."
  },
  {
    name: "ninepStop",
    commandId: "sshx11.ninepStop",
    title: "SSHX11: Stop 9P Service",
    category: "workflow",
    kind: "ops-command",
    subcommand: "9p-stop",
    description: "Stop the repo-native wv-9p service."
  },
  {
    name: "ninepPlan",
    commandId: "sshx11.ninepPlan",
    title: "SSHX11: Plan 9P Service",
    category: "workflow",
    kind: "ops-command",
    subcommand: "9p-plan",
    description: "Show the wv-9p launch plan and prerequisites without starting it."
  },
  {
    name: "openWorkflowsDoc",
    commandId: "sshx11.openWorkflowsDoc",
    title: "SSHX11: Open Workflow Documentation",
    category: "documentation",
    kind: "document",
    description: "Open the SSHX11 VS Code workflow documentation from the workspace."
  }
]);

export const SSHX11_NAMED_COMMANDS: readonly SSHX11NamedCommand[] = Object.freeze(
  SSHX11_UI_ACTIONS.map((action) => action.name)
);

export const SSHX11_FEATURE_PLUGINS: readonly SSHX11FeaturePluginDescriptor[] = Object.freeze([
  {
    id: "vfs.9p",
    name: "9P VFS Service",
    kind: "service",
    enabledByDefault: true,
    available: true,
    description: "Repo-native read-only 9P endpoint for VFS mesh and SOCKS data-path workflows.",
    provides: ["vfs.readonly.9p", "vfs.mesh.endpoint", "socks.data_path.validation", "containerized.service"],
    services: [
      {
        id: "wv-9p",
        binary: "build/bin/wv-9p",
        protocols: ["9P2000.L", "9P2000.u", "9P2000"],
        defaultListen: "127.0.0.1:5640",
        runtimes: ["host", "docker", "podman", "nerdctl"],
        readOnly: true
      }
    ],
    commands: [
      {
        id: "plan",
        opsSubcommand: "9p-plan",
        description: "Show host/container launch plan without starting the service.",
        available: true
      },
      {
        id: "start",
        opsSubcommand: "9p-start",
        description: "Start the read-only 9P service on the host or selected container runtime.",
        available: true
      },
      {
        id: "status",
        opsSubcommand: "9p-status",
        description: "Report service state, listener, runtime, and root availability.",
        available: true
      },
      {
        id: "logs",
        opsSubcommand: "9p-logs",
        description: "Read host or container runtime logs for the 9P service.",
        available: true
      },
      {
        id: "stop",
        opsSubcommand: "9p-stop",
        description: "Stop the service or remove the managed container.",
        available: true
      },
      {
        id: "image_build",
        opsSubcommand: "9p-image-build",
        description: "Build the repo-native wv-9p container image.",
        available: true
      }
    ],
    docs: [
      "README.md",
      "docs/workstation/SSHX11_9P_INTEROP_IMPLEMENTATIONS.md",
      "docs/workstation/SSHX11_VFS_MESH_PHASE1.md"
    ],
    tags: ["vfs", "9p", "service", "container", "socks"],
    missingArtifacts: [],
    missingCommands: []
  }
]);

export function listUiActions(): SSHX11UiActionDescriptor[] {
  return SSHX11_UI_ACTIONS.map((action) => ({ ...action }));
}

export function describeUiAction(name: SSHX11UiActionName): SSHX11UiActionDescriptor | undefined {
  const action = SSHX11_UI_ACTIONS.find((candidate) => candidate.name === name);
  return action ? { ...action } : undefined;
}

function cloneFeaturePlugin(plugin: SSHX11FeaturePluginDescriptor): SSHX11FeaturePluginDescriptor {
  return {
    ...plugin,
    provides: [...plugin.provides],
    services: plugin.services.map((service) => ({
      ...service,
      protocols: [...service.protocols],
      runtimes: [...service.runtimes]
    })),
    commands: plugin.commands.map((command) => ({ ...command })),
    docs: [...plugin.docs],
    tags: [...plugin.tags],
    missingArtifacts: [...plugin.missingArtifacts],
    missingCommands: [...plugin.missingCommands]
  };
}

function featurePluginMatches(plugin: SSHX11FeaturePluginDescriptor, filter: SSHX11FeaturePluginFilter = {}): boolean {
  if (filter.kind && plugin.kind !== filter.kind) {
    return false;
  }
  if (filter.feature && !plugin.provides.includes(filter.feature)) {
    return false;
  }
  if (filter.tag && !plugin.tags.includes(filter.tag)) {
    return false;
  }
  if (filter.enabledOnly && !plugin.enabledByDefault) {
    return false;
  }
  return true;
}

export function listFeaturePlugins(filter: SSHX11FeaturePluginFilter = {}): SSHX11FeaturePluginDescriptor[] {
  return SSHX11_FEATURE_PLUGINS.filter((plugin) => featurePluginMatches(plugin, filter)).map(cloneFeaturePlugin);
}

export function discoverFeaturePlugins(filter: SSHX11FeaturePluginFilter = {}): SSHX11FeaturePluginDescriptor[] {
  return listFeaturePlugins(filter);
}

export function describeFeaturePlugin(id: string): SSHX11FeaturePluginDescriptor | undefined {
  const target = String(id || "").trim();
  const plugin = SSHX11_FEATURE_PLUGINS.find((candidate) => candidate.id === target);
  return plugin ? cloneFeaturePlugin(plugin) : undefined;
}

export function isUiActionName(value: string): value is SSHX11UiActionName {
  return SSHX11_UI_ACTIONS.some((candidate) => candidate.name === value);
}

export function assertUiActionName(value: string): SSHX11UiActionName {
  if (!isUiActionName(value)) {
    throw new Error(`Unsupported SSHX11 UI action: ${value}`);
  }
  return value;
}

function expandHome(input: string, home = process.env.HOME || process.env.USERPROFILE || ""): string {
  if (!input.startsWith("~/") || !home) {
    return input;
  }
  return `${home.replace(/\/$/, "")}/${input.slice(2)}`;
}

function normalized(value: unknown): string {
  return String(value ?? "").trim();
}

function normalizedMode(value: unknown): string {
  const raw = normalized(value).toLowerCase();
  return raw === "require" || raw === "disable" ? raw : "auto";
}

function bool(value: unknown): boolean {
  return value === true;
}

function pushProxyArgs(args: string[], snapshot: SSHX11SettingsSnapshot): void {
  const sshConfig = normalized(snapshot.defaultSshConfigPath);
  const proxyJump = normalized(snapshot.defaultSshProxyJump);
  const proxyCommand = normalized(snapshot.defaultSshProxyCommand);

  if (sshConfig) {
    args.push("--ssh-config", expandHome(sshConfig));
  }
  if (proxyJump) {
    args.push("--proxy-jump", proxyJump);
  }
  if (proxyCommand) {
    args.push("--proxy-command", proxyCommand);
  }
}

function pushAgentArgs(args: string[], snapshot: SSHX11SettingsSnapshot): void {
  args.push("--agent-mode", normalizedMode(snapshot.agentMode));
  if (bool(snapshot.forwardAgent)) {
    args.push("--forward-agent");
  }

  const identityAgent = normalized(snapshot.identityAgent);
  if (identityAgent) {
    args.push("--identity-agent", expandHome(identityAgent));
  }
}

function pushRemoteRuntimeArgs(args: string[], snapshot: SSHX11SettingsSnapshot): void {
  const remotePlatform = normalized(snapshot.remotePlatform).toLowerCase();
  const remoteShellBin = normalized(snapshot.remoteShellBin);
  const remotePythonBin = normalized(snapshot.remotePythonBin);

  if (remotePlatform) {
    args.push("--remote-platform", remotePlatform);
  }
  if (remoteShellBin) {
    args.push("--remote-shell-bin", remoteShellBin);
  }
  args.push(snapshot.remoteShellLogin ? "--remote-shell-login" : "--no-remote-shell-login");
  if (remotePythonBin) {
    args.push("--remote-python-bin", remotePythonBin);
  }
}

function pushSshLoggingArgs(args: string[], snapshot: SSHX11SettingsSnapshot): void {
  const sshVerbosity = Math.max(0, Math.min(3, Number(snapshot.sshVerbosity) || 0));
  const sshLogLevel = normalized(snapshot.sshLogLevel);
  const sshLogFile = normalized(snapshot.sshLogFile);

  if (sshVerbosity > 0) {
    args.push("--ssh-verbosity", String(sshVerbosity));
  }
  if (sshLogLevel) {
    args.push("--ssh-log-level", sshLogLevel);
  }
  if (sshLogFile) {
    args.push("--ssh-log-file", expandHome(sshLogFile));
  }
}

export function buildVerifyExtensionHostsArgs(snapshot: SSHX11SettingsSnapshot): string[] {
  const args: string[] = [];
  pushProxyArgs(args, snapshot);
  pushAgentArgs(args, snapshot);
  pushRemoteRuntimeArgs(args, snapshot);
  pushSshLoggingArgs(args, snapshot);
  if (snapshot.insecureHostKey) {
    args.push("--insecure-hostkey");
  }
  return args;
}

export function buildReverseSocksSmokeArgs(
  snapshot: SSHX11SettingsSnapshot,
  request: SSHX11ReverseSocksSmokeRequest
): string[] {
  const host = normalized(request.host) || normalized(snapshot.defaultRemoteHost);
  const user = normalized(request.user) || normalized(snapshot.defaultRemoteUser);
  const identityFile = normalized(request.identityFile) || normalized(snapshot.defaultIdentityFile);
  const args = ["--host", host, "--user", user];

  if (identityFile) {
    args.push("--identity-file", expandHome(identityFile));
  }
  pushProxyArgs(args, snapshot);
  pushAgentArgs(args, snapshot);
  pushRemoteRuntimeArgs(args, snapshot);
  pushSshLoggingArgs(args, snapshot);
  if (snapshot.insecureHostKey) {
    args.push("--insecure-hostkey");
  }
  return args;
}

export function resolveUiActionPlan(
  name: SSHX11UiActionName,
  snapshot: SSHX11SettingsSnapshot,
  request: SSHX11UiActionRequest = {}
): SSHX11UiActionPlan {
  const action = describeUiAction(name);
  if (!action) {
    throw new Error(`Unsupported SSHX11 UI action: ${name}`);
  }

  switch (name) {
    case "configure":
      return { ok: true, name, kind: "configuration", action: "showConfigure" };
    case "startServices":
      return { ok: true, name, kind: "ops-command", subcommand: "service-start", args: [] };
    case "stopServices":
      return { ok: true, name, kind: "ops-command", subcommand: "service-stop", args: [] };
    case "statusLocal":
      return { ok: true, name, kind: "ops-command", subcommand: "status-local", args: [] };
    case "socksFallbackStart":
      return { ok: true, name, kind: "ops-command", subcommand: "socks-fallback-start", args: [] };
    case "vscodeProfileGen":
      return {
        ok: true,
        name,
        kind: "ops-command",
        subcommand: "vscode-profile-gen",
        args: ["--profile", "all", "--output-dir", ".vscode/sshx11"]
      };
    case "verifyExtensionHosts":
      return {
        ok: true,
        name,
        kind: "ops-command",
        subcommand: "verify-extension-hosts",
        args: buildVerifyExtensionHostsArgs(snapshot)
      };
    case "reverseSocksSmoke": {
      const host = normalized(request.host) || normalized(snapshot.defaultRemoteHost);
      const user = normalized(request.user) || normalized(snapshot.defaultRemoteUser);
      const missing: Array<"host" | "user"> = [];
      if (!host) {
        missing.push("host");
      }
      if (!user) {
        missing.push("user");
      }
      if (missing.length > 0) {
        return {
          ok: true,
          name,
          kind: "prompted-ops-command",
          subcommand: "reverse-socks-smoke",
          defaults: {
            host: snapshot.defaultRemoteHost,
            user: snapshot.defaultRemoteUser,
            identityFile: snapshot.defaultIdentityFile
          },
          missing
        };
      }
      return {
        ok: true,
        name,
        kind: "ops-command",
        subcommand: "reverse-socks-smoke",
        args: buildReverseSocksSmokeArgs(snapshot, request)
      };
    }
    case "webdavStart":
      return { ok: true, name, kind: "ops-command", subcommand: "webdav-start", args: [] };
    case "ninepStart":
      return { ok: true, name, kind: "ops-command", subcommand: "9p-start", args: [] };
    case "ninepStatus":
      return { ok: true, name, kind: "ops-command", subcommand: "9p-status", args: [] };
    case "ninepStop":
      return { ok: true, name, kind: "ops-command", subcommand: "9p-stop", args: [] };
    case "ninepPlan":
      return { ok: true, name, kind: "ops-command", subcommand: "9p-plan", args: [] };
    case "openWorkflowsDoc":
      return {
        ok: true,
        name,
        kind: "document",
        relativePath: "docs/workstation/SSHX11_VSCODE_EXTENSION_NETWORK_WORKFLOWS.md"
      };
  }
}
