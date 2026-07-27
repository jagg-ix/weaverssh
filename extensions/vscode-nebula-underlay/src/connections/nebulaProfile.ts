import { readFile } from "fs/promises";
import * as path from "path";

export const WORKSPACE_PROFILE_VERSION = "weaverssh.workspace.v1";

export interface NebulaConnectionProfile {
  type: "ssh";
  ssh_host: string;
  underlay?: "nebula";
  overlay_address?: string;
}

export interface SessionHostLaunchProfile {
  local_root?: string;
  node_context: string;
  public_key_file: string;
  extra_args?: string[];
  ssh_args?: string[];
}

export interface WeaverSSHWorkspaceProfile {
  version: typeof WORKSPACE_PROFILE_VERSION;
  target_node: string;
  connection: NebulaConnectionProfile;
  remote_root: string;
  session_host?: SessionHostLaunchProfile;
  services?: Array<{
    name: string;
    node: string;
    address: string;
  }>;
}

function requireString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`${field} must be a non-empty string`);
  }
  return value.trim();
}

function optionalString(value: unknown, field: string): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  return requireString(value, field);
}

function stringArray(value: unknown, field: string): string[] | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string")) {
    throw new Error(`${field} must be an array of strings`);
  }
  return value.map((entry) => entry.trim()).filter(Boolean);
}

export function parseNebulaProfile(value: unknown): WeaverSSHWorkspaceProfile {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("workspace profile must be an object");
  }
  const raw = value as Record<string, unknown>;
  const version = requireString(raw.version, "version");
  if (version !== WORKSPACE_PROFILE_VERSION) {
    throw new Error(`unsupported workspace profile version ${version}`);
  }

  if (!raw.connection || typeof raw.connection !== "object" || Array.isArray(raw.connection)) {
    throw new Error("connection must be an object");
  }
  const connectionRaw = raw.connection as Record<string, unknown>;
  const type = requireString(connectionRaw.type, "connection.type");
  if (type !== "ssh") {
    throw new Error("connection.type must be ssh");
  }
  const underlay = optionalString(connectionRaw.underlay, "connection.underlay");
  if (underlay !== undefined && underlay !== "nebula") {
    throw new Error("connection.underlay must be nebula when present");
  }

  let sessionHost: SessionHostLaunchProfile | undefined;
  if (raw.session_host !== undefined) {
    if (!raw.session_host || typeof raw.session_host !== "object" || Array.isArray(raw.session_host)) {
      throw new Error("session_host must be an object");
    }
    const launch = raw.session_host as Record<string, unknown>;
    sessionHost = {
      local_root: optionalString(launch.local_root, "session_host.local_root"),
      node_context: requireString(launch.node_context, "session_host.node_context"),
      public_key_file: requireString(launch.public_key_file, "session_host.public_key_file"),
      extra_args: stringArray(launch.extra_args, "session_host.extra_args"),
      ssh_args: stringArray(launch.ssh_args, "session_host.ssh_args")
    };
  }

  return {
    version: WORKSPACE_PROFILE_VERSION,
    target_node: requireString(raw.target_node, "target_node"),
    connection: {
      type: "ssh",
      ssh_host: requireString(connectionRaw.ssh_host, "connection.ssh_host"),
      underlay: underlay as "nebula" | undefined,
      overlay_address: optionalString(connectionRaw.overlay_address, "connection.overlay_address")
    },
    remote_root: requireString(raw.remote_root, "remote_root"),
    session_host: sessionHost,
    services: Array.isArray(raw.services) ? raw.services.map((entry, index) => {
      if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
        throw new Error(`services[${index}] must be an object`);
      }
      const service = entry as Record<string, unknown>;
      return {
        name: requireString(service.name, `services[${index}].name`),
        node: requireString(service.node, `services[${index}].node`),
        address: requireString(service.address, `services[${index}].address`)
      };
    }) : undefined
  };
}

export async function loadNebulaProfile(profilePath: string): Promise<WeaverSSHWorkspaceProfile> {
  const payload = await readFile(profilePath, "utf8");
  let decoded: unknown;
  try {
    decoded = JSON.parse(payload);
  } catch (error) {
    throw new Error(`parse ${profilePath}: ${error instanceof Error ? error.message : String(error)}`);
  }
  return parseNebulaProfile(decoded);
}

export function resolveWorkspacePath(workspaceRoot: string, configuredPath: string): string {
  const trimmed = configuredPath.trim();
  if (path.isAbsolute(trimmed)) {
    return trimmed;
  }
  return path.join(workspaceRoot, trimmed);
}
