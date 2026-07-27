import { execFile } from "child_process";
import { promisify } from "util";
import type { WeaverSSHWorkspaceProfile } from "../connections/nebulaProfile";

const execFileAsync = promisify(execFile);

export interface ConnectivityCheck {
  name: string;
  ok: boolean;
  detail?: string;
}

interface ConnectivityStatus {
  version: string;
  underlay: string;
  ssh_host: string;
  resolved_host?: string;
  resolved_port?: number;
  resolved_user?: string;
  overlay_address?: string;
  ssh_config_resolved: boolean;
  overlay_reachable: boolean;
  ssh_reachable: boolean;
  weaverssh_checked: boolean;
  weaverssh_ready: boolean;
  weaverssh_detail?: string;
  checks: ConnectivityCheck[];
}

export interface NebulaStatus extends ConnectivityStatus {
  nebula_detected: boolean;
  nebula_executable?: string;
}

function parseStatus(output: string): ConnectivityStatus {
  const decoded = JSON.parse(output) as ConnectivityStatus;
  if (decoded.version !== "weaverssh.connectivity.v1" || !Array.isArray(decoded.checks)) {
    throw new Error("wv returned an unsupported connectivity result");
  }
  return decoded;
}

async function addNebulaExecutableStatus(
  status: ConnectivityStatus,
  timeoutMs: number
): Promise<NebulaStatus> {
  try {
    await execFileAsync("nebula", ["-version"], {
      timeout: timeoutMs,
      maxBuffer: 1024 * 1024
    });
    return { ...status, nebula_detected: true, nebula_executable: "nebula" };
  } catch {
    return { ...status, nebula_detected: false };
  }
}

export async function readNebulaStatus(
  profile: WeaverSSHWorkspaceProfile,
  wvBinary: string,
  timeoutMs: number
): Promise<NebulaStatus> {
  const args = [
    "connectivity", "check", "--json", "--underlay", "nebula",
    "--ssh-host", profile.connection.ssh_host,
    "--timeout", `${Math.max(1, Math.ceil(timeoutMs / 1000))}s`
  ];
  if (profile.connection.overlay_address) {
    args.push("--overlay-address", profile.connection.overlay_address);
  }

  try {
    const { stdout } = await execFileAsync(wvBinary, args, {
      timeout: timeoutMs * 3,
      maxBuffer: 1024 * 1024
    });
    return addNebulaExecutableStatus(parseStatus(stdout.trim()), timeoutMs);
  } catch (error) {
    const candidate = error as Error & { stdout?: string | Buffer; stderr?: string | Buffer };
    const stdout = candidate.stdout === undefined ? "" : String(candidate.stdout).trim();
    if (stdout) {
      return addNebulaExecutableStatus(parseStatus(stdout), timeoutMs);
    }
    const stderr = candidate.stderr === undefined ? "" : String(candidate.stderr).trim();
    throw new Error(stderr || candidate.message || "wv connectivity check failed");
  }
}

export function formatNebulaStatus(profile: WeaverSSHWorkspaceProfile, status: NebulaStatus): string {
  const route = status.ssh_reachable ? "available" : "unavailable";
  return [
    `WeaverSSH: ${profile.target_node}`,
    "Connection: SSH over Nebula",
    `Overlay address: ${status.overlay_address || status.resolved_host || "unresolved"}`,
    `SSH route: ${route}`,
    `Session: ${status.weaverssh_ready ? "authenticated" : "not active"}`,
    `Nebula executable: ${status.nebula_detected ? status.nebula_executable || "detected" : "not found in PATH"}`
  ].join("\n");
}
