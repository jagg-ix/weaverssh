import { execFile } from "child_process";
import { promisify } from "util";

const execFileAsync = promisify(execFile);
const SESSION_API_PROTOCOL = "weaverssh.session-api.v1";

export interface SessionNode {
  id: string;
  index: number;
  registered: boolean;
  services?: string[];
}

export interface SessionSnapshot {
  protocol: string;
  binding: string;
  current_node: string;
  current_index: number;
  topology: string[];
  nodes: SessionNode[];
  features: string[];
}

export interface SessionRoute {
  target_node: string;
  target_index: number;
  direction: string;
  next_hop?: string;
  next_binding?: string;
  service?: string;
  available: boolean;
  uses_current_session?: boolean;
}

export interface SessionRuntimeStatus {
  snapshot: SessionSnapshot;
  route: SessionRoute;
  targetNode: SessionNode;
  routeLabel: string;
}

function requireObject(value: unknown, name: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${name} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requireString(value: unknown, name: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`${name} must be a non-empty string`);
  }
  return value.trim();
}

function requireBoolean(value: unknown, name: string): boolean {
  if (typeof value !== "boolean") {
    throw new Error(`${name} must be boolean`);
  }
  return value;
}

function requireIndex(value: unknown, name: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
    throw new Error(`${name} must be a non-negative integer`);
  }
  return value;
}

function requireStringArray(value: unknown, name: string): string[] {
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string")) {
    throw new Error(`${name} must be an array of strings`);
  }
  return value.map((entry) => entry.trim()).filter(Boolean);
}

function nullableStringArray(value: unknown, name: string): string[] {
  if (value === undefined || value === null) {
    return [];
  }
  return requireStringArray(value, name);
}

function parseJSON(output: string, name: string): unknown {
  try {
    return JSON.parse(output);
  } catch (error) {
    throw new Error(`parse ${name}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

export function parseSessionSnapshot(output: string): SessionSnapshot {
  const raw = requireObject(parseJSON(output, "wv api describe"), "session snapshot");
  const protocol = requireString(raw.protocol, "protocol");
  if (protocol !== SESSION_API_PROTOCOL) {
    throw new Error(`unsupported session API protocol ${protocol}`);
  }
  const topology = requireStringArray(raw.topology, "topology");
  if (new Set(topology).size !== topology.length) {
    throw new Error("session topology contains duplicate node IDs");
  }
  const nodesRaw = raw.nodes;
  if (!Array.isArray(nodesRaw)) {
    throw new Error("session snapshot nodes must be an array");
  }
  const nodes = nodesRaw.map((entry, index): SessionNode => {
    const node = requireObject(entry, `nodes[${index}]`);
    const parsed = {
      id: requireString(node.id, `nodes[${index}].id`),
      index: requireIndex(node.index, `nodes[${index}].index`),
      registered: requireBoolean(node.registered, `nodes[${index}].registered`),
      services: node.services === undefined || node.services === null
        ? undefined
        : requireStringArray(node.services, `nodes[${index}].services`)
    };
    if (topology[parsed.index] !== parsed.id) {
      throw new Error(`nodes[${index}] does not match topology index ${parsed.index}`);
    }
    return parsed;
  });
  const currentIndex = requireIndex(raw.current_index, "current_index");
  const currentNode = requireString(raw.current_node, "current_node");
  if (topology[currentIndex] !== currentNode) {
    throw new Error("current_node does not match current_index in topology");
  }
  return {
    protocol,
    binding: requireString(raw.binding, "binding"),
    current_node: currentNode,
    current_index: currentIndex,
    topology,
    nodes,
    features: nullableStringArray(raw.features, "features")
  };
}

export function parseSessionRoute(output: string): SessionRoute {
  const raw = requireObject(parseJSON(output, "wv api route"), "session route");
  return {
    target_node: requireString(raw.target_node, "target_node"),
    target_index: requireIndex(raw.target_index, "target_index"),
    direction: requireString(raw.direction, "direction"),
    next_hop: raw.next_hop === undefined ? undefined : requireString(raw.next_hop, "next_hop"),
    next_binding: raw.next_binding === undefined ? undefined : requireString(raw.next_binding, "next_binding"),
    service: raw.service === undefined ? undefined : requireString(raw.service, "service"),
    available: requireBoolean(raw.available, "available"),
    uses_current_session: raw.uses_current_session === undefined ? undefined : requireBoolean(raw.uses_current_session, "uses_current_session")
  };
}

async function runWV(wvBinary: string, args: string[], timeoutMs: number): Promise<string> {
  try {
    const { stdout } = await execFileAsync(wvBinary, args, {
      timeout: timeoutMs,
      maxBuffer: 1024 * 1024
    });
    return String(stdout).trim();
  } catch (error) {
    const candidate = error as Error & { stdout?: string | Buffer; stderr?: string | Buffer };
    const stderr = candidate.stderr === undefined ? "" : String(candidate.stderr).trim();
    throw new Error(stderr || candidate.message || `${wvBinary} ${args.join(" ")} failed`);
  }
}

function routeLabel(route: SessionRoute): string {
  if (!route.available) {
    return "unavailable";
  }
  if (route.uses_current_session) {
    return "direct";
  }
  if (route.next_hop) {
    return `via ${route.next_hop}`;
  }
  return route.direction || "available";
}

export async function readSessionStatus(
  wvBinary: string,
  targetNodeID: string,
  timeoutMs: number
): Promise<SessionRuntimeStatus> {
  const snapshot = parseSessionSnapshot(await runWV(wvBinary, ["api", "--json", "describe"], timeoutMs));
  const targetNode = snapshot.nodes.find((node) => node.id === targetNodeID && node.registered);
  if (!targetNode) {
    throw new Error(`signed target node ${targetNodeID} is not registered in the active WeaverSSH session`);
  }
  const route = parseSessionRoute(await runWV(wvBinary, ["api", "--json", "route", targetNodeID], timeoutMs));
  if (route.target_node !== targetNodeID) {
    throw new Error(`route response selected ${route.target_node}, expected ${targetNodeID}`);
  }
  if (route.target_index !== targetNode.index) {
    throw new Error(`route target index ${route.target_index} does not match signed node index ${targetNode.index}`);
  }
  if (!route.available) {
    throw new Error(`route to signed target node ${targetNodeID} is unavailable`);
  }
  return { snapshot, route, targetNode, routeLabel: routeLabel(route) };
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

export async function waitForSession(
  wvBinary: string,
  targetNodeID: string,
  waitTimeoutMs: number,
  pollIntervalMs: number
): Promise<SessionRuntimeStatus> {
  const deadline = Date.now() + Math.max(1, waitTimeoutMs);
  const interval = Math.max(100, pollIntervalMs);
  let lastError = "session broker not ready";
  while (Date.now() < deadline) {
    const remaining = deadline - Date.now();
    try {
      return await readSessionStatus(wvBinary, targetNodeID, Math.max(250, Math.min(5000, remaining)));
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
    }
    await sleep(Math.min(interval, Math.max(1, deadline - Date.now())));
  }
  throw new Error(`timed out waiting for authenticated WeaverSSH session for ${targetNodeID}: ${lastError}`);
}
