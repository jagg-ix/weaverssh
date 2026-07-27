import { parseSessionRoute, parseSessionSnapshot } from "../src/session/sessionStatus";

function expect(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const snapshot = parseSessionSnapshot(JSON.stringify({
  protocol: "weaverssh.session-api.v1",
  binding: "binding-1",
  current_node: "workstation",
  current_index: 0,
  topology: ["workstation", "dev-node-1"],
  nodes: [
    { id: "workstation", index: 0, registered: true },
    { id: "dev-node-1", index: 1, registered: true, services: ["fs", "tcp"] }
  ],
  features: null
}));
expect(snapshot.binding === "binding-1", "snapshot binding was not parsed");
expect(snapshot.features.length === 0, "null feature slice should normalize to an empty array");
expect(snapshot.nodes[1]?.services?.includes("tcp") === true, "target services were not parsed");

const route = parseSessionRoute(JSON.stringify({
  target_node: "dev-node-1",
  target_index: 1,
  direction: "next",
  available: true,
  uses_current_session: true
}));
expect(route.target_node === "dev-node-1", "route target was not parsed");
expect(route.available, "route availability was not parsed");

let rejected = false;
try {
  parseSessionSnapshot("{}");
} catch {
  rejected = true;
}
expect(rejected, "invalid session snapshot was accepted");

rejected = false;
try {
  parseSessionSnapshot(JSON.stringify({
    protocol: "weaverssh.session-api.v0",
    binding: "binding-1",
    current_node: "workstation",
    current_index: 0,
    topology: ["workstation"],
    nodes: [{ id: "workstation", index: 0, registered: true }],
    features: []
  }));
} catch {
  rejected = true;
}
expect(rejected, "unsupported session API protocol was accepted");

rejected = false;
try {
  parseSessionSnapshot(JSON.stringify({
    protocol: "weaverssh.session-api.v1",
    binding: "binding-1",
    current_node: "workstation",
    current_index: 0,
    topology: ["workstation", "dev-node-1"],
    nodes: [{ id: "dev-node-1", index: 0, registered: true }],
    features: []
  }));
} catch {
  rejected = true;
}
expect(rejected, "node/topology index mismatch was accepted");

console.log("session status contract tests: ok");
