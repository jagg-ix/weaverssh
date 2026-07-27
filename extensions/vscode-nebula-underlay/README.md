# WeaverSSH Nebula Underlay extension

This optional VS Code extension treats Nebula only as the private IP path used by OpenSSH.
It does not read Nebula certificates, derive WeaverSSH capabilities from Nebula groups, or
modify WeaverSSH protocol messages.

Commands:

```text
WeaverSSH: Diagnose Nebula Node
WeaverSSH: Connect Nebula Node
WeaverSSH: Refresh Nebula Session Status
```

`Connect Nebula Node` first validates SSH reachability, launches the ordinary
`wv session-host ... -- ssh -X HOST` command, waits for the local WeaverSSH broker,
then verifies through `wv api describe` that the profile's signed target node is
registered. It also resolves the live route and updates a status-bar item with the
authenticated session and route state.

The status-bar item is itself a refresh command. Network reachability never substitutes
for WeaverSSH node-context verification or endpoint authorization.

Configuration is read from `.weaverssh/workspace.json` by default. See
`deploy/nebula/workspace.nebula.json.example` and `docs/usage/nebula-underlay.md`.
