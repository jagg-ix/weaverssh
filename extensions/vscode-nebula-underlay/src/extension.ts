import * as vscode from "vscode";
import { registerNebulaCommands } from "./commands/connectNebulaNode";

export function activate(context: vscode.ExtensionContext): void {
  registerNebulaCommands(context);
}

export function deactivate(): void {
  // no-op
}
