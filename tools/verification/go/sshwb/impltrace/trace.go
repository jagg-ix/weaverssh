package impltrace

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

const SourceName = "weaverssh_go_ast_impltrace"

type RuntimeContext struct {
	Perspective string `json:"perspective"`
	FlowPlane   string `json:"flow_plane"`
	Role        string `json:"role"`
}

type TLAAnchor struct {
	Module string `json:"module"`
	Action string `json:"action"`
}

type ImplementationAnchor struct {
	RepoRoot string `json:"repo_root"`
	File     string `json:"file"`
	Symbol   string `json:"symbol"`
	Kind     string `json:"kind"`
	Line     int    `json:"line"`
}

type EventRecord struct {
	Source         string               `json:"source"`
	Trace          string               `json:"trace"`
	StepIndex      int                  `json:"step_index"`
	Actor          string               `json:"actor"`
	Event          string               `json:"event"`
	Arg            *int                 `json:"arg"`
	RuntimeContext RuntimeContext       `json:"runtime_context"`
	TLA            TLAAnchor            `json:"tla"`
	Implementation ImplementationAnchor `json:"implementation"`
}

type eventSpec struct {
	actor     string
	event     string
	arg       *int
	file      string
	symbol    string
	kind      string
	tlaModule string
	tlaAction string
}

type symbolAnchor struct {
	file   string
	symbol string
	kind   string
	line   int
}

func intPtr(v int) *int { return &v }

func actorRuntimeContext(actor string) RuntimeContext {
	switch actor {
	case "sshClient":
		return RuntimeContext{Perspective: "userEdgeHost", FlowPlane: "sshTransportControl", Role: "sshClientProcess"}
	case "sshServer":
		return RuntimeContext{Perspective: "sshServerHost", FlowPlane: "sshTransportControl", Role: "sshServerProcess"}
	case "x11Producer":
		return RuntimeContext{Perspective: "userEdgeHost", FlowPlane: "x11PayloadStream", Role: "edgeX11Producer"}
	case "bridgeServer":
		return RuntimeContext{Perspective: "bridgeHost", FlowPlane: "websocketControl", Role: "bridgeServerProcess"}
	case "bridgeClient":
		return RuntimeContext{Perspective: "bridgeHost", FlowPlane: "websocketControl", Role: "bridgeClientProcess"}
	default:
		return RuntimeContext{}
	}
}

func specs() []eventSpec {
	const fsm = "SSHX11CryptoCrossLayerContract"
	const t1 = "SSHX11ForwardWebSocketHandshake"
	return []eventSpec{
		{actor: "sshClient", event: "start", file: "tools/verification/go/sshwb/sshunit/core.go", symbol: "BuildSSHArgs", kind: "function", tlaModule: fsm, tlaAction: "SSHClientTransitions.start"},
		{actor: "sshServer", event: "acceptTransport", file: "internal/app/x11_server_fsm.go", symbol: "X11Server.Start", kind: "method", tlaModule: fsm, tlaAction: "SSHServerTransitions.acceptTransport"},
		{actor: "sshClient", event: "keyExchangeDone", file: "tools/verification/go/sshwb/sshunit/core.go", symbol: "BuildSSHArgs", kind: "function", tlaModule: fsm, tlaAction: "SSHClientTransitions.keyExchangeDone"},
		{actor: "sshServer", event: "keyExchangeDone", file: "internal/app/x11_server_fsm.go", symbol: "X11Server.handleConnection", kind: "method", tlaModule: fsm, tlaAction: "SSHServerTransitions.keyExchangeDone"},
		{actor: "sshClient", event: "userAuthDone", file: "tools/verification/go/sshwb/sshunit/core.go", symbol: "BuildSSHArgs", kind: "function", tlaModule: fsm, tlaAction: "SSHClientTransitions.userAuthDone"},
		{actor: "sshServer", event: "userAuthDone", file: "internal/app/x11_server_fsm.go", symbol: "X11Server.handleConnection", kind: "method", tlaModule: fsm, tlaAction: "SSHServerTransitions.userAuthDone"},
		{actor: "sshClient", event: "requestX11ForwardX", file: "tools/verification/go/sshwb/sshunit/core.go", symbol: "BuildSSHArgs", kind: "function", tlaModule: fsm, tlaAction: "SSHClientTransitions.requestX11ForwardX"},
		{actor: "sshServer", event: "enableX11Forward", file: "internal/app/x11_server_fsm.go", symbol: "NewX11Server", kind: "function", tlaModule: fsm, tlaAction: "SSHServerTransitions.enableX11Forward"},
		{actor: "sshServer", event: "generateMITMagicCookie", file: "internal/app/x11_server_fsm.go", symbol: "X11Server.handleGenerateAuthorization", kind: "method", tlaModule: fsm, tlaAction: "SSHServerTransitions.generateMITMagicCookie"},
		{actor: "sshServer", event: "xauthAddMITMagicCookie", file: "internal/app/x11_server_fsm.go", symbol: "X11Server.writeToXauth", kind: "method", tlaModule: fsm, tlaAction: "SSHServerTransitions.xauthAddMITMagicCookie"},
		{actor: "sshServer", event: "issueX11ProxyCookie", file: "internal/app/x11_server_fsm.go", symbol: "Authorization", kind: "type", tlaModule: fsm, tlaAction: "SSHServerTransitions.issueX11ProxyCookie"},
		{actor: "sshClient", event: "openSession", file: "tools/verification/go/sshwb/sshunit/core.go", symbol: "Channel.Open", kind: "method", tlaModule: fsm, tlaAction: "SSHClientTransitions.openSession"},
		{actor: "sshClient", event: "verifyMitMagicCookie", file: "internal/app/x11_protocol_types.go", symbol: "AuthProtoMITMagicCookie", kind: "const", tlaModule: fsm, tlaAction: "SSHClientTransitions.verifyMitMagicCookie"},
		{actor: "sshServer", event: "openSession", file: "internal/app/x11_server_fsm.go", symbol: "X11Server.handleConnection", kind: "method", tlaModule: fsm, tlaAction: "SSHServerTransitions.openSession"},
		{actor: "sshClient", event: "openX11Channel", file: "tools/verification/go/sshwb/sshunit/core.go", symbol: "Channel.Open", kind: "method", tlaModule: fsm, tlaAction: "SSHClientTransitions.openX11Channel"},
		{actor: "sshServer", event: "acceptX11Channel", file: "internal/app/x11_server_fsm.go", symbol: "X11Server.handleConnection", kind: "method", tlaModule: fsm, tlaAction: "SSHServerTransitions.acceptX11Channel"},
		{actor: "x11Producer", event: "openSocket", file: "internal/app/socks.go", symbol: "SOCKSHandler.handleX11Connection", kind: "method", tlaModule: fsm, tlaAction: "X11ProducerTransitions.openSocket"},
		{actor: "x11Producer", event: "sendSetup", file: "internal/app/socks.go", symbol: "createX11SetupRequest", kind: "function", tlaModule: t1, tlaAction: "RecvSetup"},
		{actor: "x11Producer", event: "setupAccepted", file: "internal/app/x11_server_fsm.go", symbol: "X11Server.buildConnectionReply", kind: "method", tlaModule: t1, tlaAction: "AuthSucceed"},
		{actor: "bridgeServer", event: "beginHandshake", file: "internal/app/x11_server_fsm.go", symbol: "X11Server.processConnectionSetup", kind: "method", tlaModule: t1, tlaAction: "RecvSetup"},
		{actor: "bridgeServer", event: "authOK", file: "internal/app/x11_server_fsm.go", symbol: "X11Server.validateAuth", kind: "method", tlaModule: t1, tlaAction: "AuthSucceed"},
		{actor: "bridgeClient", event: "openSocket", file: "internal/app/socks.go", symbol: "SOCKSHandler.handleX11Connection", kind: "method", tlaModule: fsm, tlaAction: "BridgeClientTransitions.openSocket"},
		{actor: "bridgeClient", event: "sendX11Setup", file: "internal/app/socks.go", symbol: "createX11SetupRequest", kind: "function", tlaModule: t1, tlaAction: "RecvSetup"},
		{actor: "bridgeClient", event: "x11SetupAccepted", file: "internal/app/x11_server_fsm.go", symbol: "X11Server.buildConnectionReply", kind: "method", tlaModule: t1, tlaAction: "AuthSucceed"},
		{actor: "bridgeClient", event: "presentProxyCookie", file: "internal/app/socks.go", symbol: "createX11SetupRequest", kind: "function", tlaModule: fsm, tlaAction: "BridgeClientTransitions.presentProxyCookie"},
		{actor: "bridgeServer", event: "verifyProxyCookie", file: "internal/app/x11_server_fsm.go", symbol: "X11Server.validateAuth", kind: "method", tlaModule: fsm, tlaAction: "BridgeServerTransitions.verifyProxyCookie"},
		{actor: "bridgeServer", event: "websocketUpgradeRequested", file: "internal/app/x11_websocket_upgrade.go", symbol: "MultiProtocolConnection.UpgradeToWebSocket", kind: "method", tlaModule: t1, tlaAction: "RecvValidUpgrade"},
		{actor: "bridgeClient", event: "requestWSUpgrade", file: "tunnel/upgrade.go", symbol: "ClientUpgrade", kind: "function", tlaModule: t1, tlaAction: "RecvValidUpgrade"},
		{actor: "bridgeServer", event: "websocketUpgradeSucceeded", file: "internal/app/x11_websocket_upgrade.go", symbol: "ProtocolWebSocket", kind: "const", tlaModule: t1, tlaAction: "CompleteUpgrade"},
		{actor: "bridgeClient", event: "wsUpgradeSucceeded", file: "tunnel/upgrade.go", symbol: "ClientUpgrade", kind: "function", tlaModule: t1, tlaAction: "CompleteUpgrade"},
		{actor: "bridgeClient", event: "syncBufferProfiles", file: "tunnel/upgrade.go", symbol: "ClientUpgrade", kind: "function", tlaModule: fsm, tlaAction: "BridgeClientTransitions.syncBufferProfiles"},
		{actor: "bridgeClient", event: "startRelay", file: "relay/relay.go", symbol: "Relay.Start", kind: "method", tlaModule: fsm, tlaAction: "BridgeClientTransitions.startRelay"},
		{actor: "x11Producer", event: "sendPayload", file: "relay/relay.go", symbol: "Relay.Start", kind: "method", tlaModule: fsm, tlaAction: "X11ProducerTransitions.sendPayload"},
		{actor: "bridgeServer", event: "relayClientToTarget", arg: intPtr(128), file: "relay/relay.go", symbol: "Relay.trackBytesSent", kind: "method", tlaModule: fsm, tlaAction: "BridgeServerTransitions.relayClientToTarget"},
		{actor: "bridgeServer", event: "relayTargetToClient", arg: intPtr(64), file: "relay/relay.go", symbol: "Relay.trackBytesReceived", kind: "method", tlaModule: fsm, tlaAction: "BridgeServerTransitions.relayTargetToClient"},
	}
}

func Emit(repoRoot string) ([]EventRecord, error) {
	repoRoot = filepath.Clean(repoRoot)
	anchors, err := collectAnchors(repoRoot, specs())
	if err != nil {
		return nil, err
	}
	out := make([]EventRecord, 0, len(specs()))
	for i, spec := range specs() {
		key := anchorKey(spec.file, spec.symbol, spec.kind)
		anchor, ok := anchors[key]
		if !ok {
			return nil, fmt.Errorf("missing Go anchor: file=%s symbol=%s kind=%s", spec.file, spec.symbol, spec.kind)
		}
		out = append(out, EventRecord{
			Source:         SourceName,
			Trace:          "goRuntimeCanonicalTrace",
			StepIndex:      i,
			Actor:          spec.actor,
			Event:          spec.event,
			Arg:            spec.arg,
			RuntimeContext: actorRuntimeContext(spec.actor),
			TLA:            TLAAnchor{Module: spec.tlaModule, Action: spec.tlaAction},
			Implementation: ImplementationAnchor{
				RepoRoot: repoRoot,
				File:     anchor.file,
				Symbol:   anchor.symbol,
				Kind:     anchor.kind,
				Line:     anchor.line,
			},
		})
	}
	return out, nil
}

func WriteNDJSON(path string, records []EventRecord) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	for _, rec := range records {
		if err := enc.Encode(rec); err != nil {
			return err
		}
	}
	return nil
}

func anchorKey(file, symbol, kind string) string {
	return filepath.ToSlash(file) + "\x00" + symbol + "\x00" + kind
}

func collectAnchors(repoRoot string, specs []eventSpec) (map[string]symbolAnchor, error) {
	wanted := map[string]eventSpec{}
	files := map[string]bool{}
	for _, spec := range specs {
		file := filepath.ToSlash(spec.file)
		wanted[anchorKey(file, spec.symbol, spec.kind)] = spec
		files[file] = true
	}

	out := map[string]symbolAnchor{}
	for file := range files {
		abs := filepath.Join(repoRoot, filepath.FromSlash(file))
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, abs, nil, 0)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", file, err)
		}
		for _, decl := range parsed.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				kind := "function"
				symbol := d.Name.Name
				if d.Recv != nil && len(d.Recv.List) > 0 {
					kind = "method"
					symbol = receiverName(d.Recv.List[0].Type) + "." + d.Name.Name
				}
				key := anchorKey(file, symbol, kind)
				if _, ok := wanted[key]; ok {
					out[key] = symbolAnchor{file: file, symbol: symbol, kind: kind, line: fset.Position(d.Pos()).Line}
				}
			case *ast.GenDecl:
				kind := ""
				switch d.Tok {
				case token.CONST:
					kind = "const"
				case token.TYPE:
					kind = "type"
				default:
					continue
				}
				for _, spec := range d.Specs {
					var name string
					switch s := spec.(type) {
					case *ast.ValueSpec:
						for _, n := range s.Names {
							name = n.Name
							key := anchorKey(file, name, kind)
							if _, ok := wanted[key]; ok {
								out[key] = symbolAnchor{file: file, symbol: name, kind: kind, line: fset.Position(n.Pos()).Line}
							}
						}
					case *ast.TypeSpec:
						name = s.Name.Name
						key := anchorKey(file, name, kind)
						if _, ok := wanted[key]; ok {
							out[key] = symbolAnchor{file: file, symbol: name, kind: kind, line: fset.Position(s.Pos()).Line}
						}
					}
				}
			}
		}
	}
	return out, nil
}

func receiverName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return receiverName(t.X)
	case *ast.SelectorExpr:
		prefix := receiverName(t.X)
		if prefix == "" {
			return t.Sel.Name
		}
		return prefix + "." + t.Sel.Name
	default:
		return strings.TrimSpace(fmt.Sprintf("%T", expr))
	}
}
