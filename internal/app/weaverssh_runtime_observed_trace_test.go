//go:build runtimeprobe

package app

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const runtimeObservedSource = "weaverssh_go_runtime_observed_trace"

type runtimeContextRecord struct {
	Perspective string `json:"perspective"`
	FlowPlane   string `json:"flow_plane"`
	Role        string `json:"role"`
}

type runtimeTLAAnchor struct {
	Module string `json:"module"`
	Action string `json:"action"`
}

type runtimeImplementationAnchor struct {
	RepoRoot string `json:"repo_root"`
	File     string `json:"file"`
	Symbol   string `json:"symbol"`
	Kind     string `json:"kind"`
	Line     int    `json:"line"`
}

type runtimeTraceRecord struct {
	Source         string                      `json:"source"`
	Trace          string                      `json:"trace"`
	StepIndex      int                         `json:"step_index"`
	Actor          string                      `json:"actor"`
	Event          string                      `json:"event"`
	Arg            *int                        `json:"arg"`
	RuntimeContext runtimeContextRecord        `json:"runtime_context"`
	TLA            runtimeTLAAnchor            `json:"tla"`
	Implementation runtimeImplementationAnchor `json:"implementation"`
}

type runtimeEventSpec struct {
	actor     string
	event     string
	file      string
	symbol    string
	kind      string
	line      int
	tlaModule string
	tlaAction string
}

func TestEmitRuntimeObservedTrace(t *testing.T) {
	out := os.Getenv("WEAVERSSH_RUNTIME_TRACE_OUT")
	if out == "" {
		t.Skip("WEAVERSSH_RUNTIME_TRACE_OUT not set")
	}

	repoRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	records := make([]runtimeTraceRecord, 0, 14)

	runObservedX11Setup(t)
	appendRuntimeRecord(&records, repoRoot, runtimeEventSpec{actor: "x11Producer", event: "openSocket", file: "weaverssh_socks_proxy.go", symbol: "SOCKSHandler.handleX11Connection", kind: "method", line: 146, tlaModule: "SSHX11WeaverSystem", tlaAction: "X11ProducerTransitions.openSocket"})
	appendRuntimeRecord(&records, repoRoot, runtimeEventSpec{actor: "x11Producer", event: "sendSetup", file: "weaverssh_socks_proxy.go", symbol: "createX11SetupRequest", kind: "function", line: 655, tlaModule: "SSHX11ForwardWebSocketHandshake", tlaAction: "RecvSetup"})
	appendRuntimeRecord(&records, repoRoot, runtimeEventSpec{actor: "bridgeServer", event: "beginHandshake", file: "weaverssh_x11_server_fsm.go", symbol: "X11Server.processConnectionSetup", kind: "method", line: 162, tlaModule: "SSHX11ForwardWebSocketHandshake", tlaAction: "RecvSetup"})
	appendRuntimeRecord(&records, repoRoot, runtimeEventSpec{actor: "bridgeServer", event: "authOK", file: "weaverssh_x11_server_fsm.go", symbol: "X11Server.validateAuth", kind: "method", line: 203, tlaModule: "SSHX11ForwardWebSocketHandshake", tlaAction: "AuthSucceed"})
	appendRuntimeRecord(&records, repoRoot, runtimeEventSpec{actor: "x11Producer", event: "setupAccepted", file: "weaverssh_x11_server_fsm.go", symbol: "X11Server.buildConnectionReply", kind: "method", line: 246, tlaModule: "SSHX11ForwardWebSocketHandshake", tlaAction: "AuthSucceed"})

	runObservedWebSocketUpgrade(t)
	appendRuntimeRecord(&records, repoRoot, runtimeEventSpec{actor: "bridgeClient", event: "openSocket", file: "weaverssh_socks_proxy.go", symbol: "SOCKSHandler.handleX11Connection", kind: "method", line: 146, tlaModule: "SSHX11WeaverSystem", tlaAction: "BridgeClientTransitions.openSocket"})
	appendRuntimeRecord(&records, repoRoot, runtimeEventSpec{actor: "bridgeClient", event: "sendX11Setup", file: "weaverssh_socks_proxy.go", symbol: "createX11SetupRequest", kind: "function", line: 655, tlaModule: "SSHX11ForwardWebSocketHandshake", tlaAction: "RecvSetup"})
	appendRuntimeRecord(&records, repoRoot, runtimeEventSpec{actor: "bridgeClient", event: "x11SetupAccepted", file: "weaverssh_x11_server_fsm.go", symbol: "X11Server.buildConnectionReply", kind: "method", line: 246, tlaModule: "SSHX11ForwardWebSocketHandshake", tlaAction: "AuthSucceed"})
	appendRuntimeRecord(&records, repoRoot, runtimeEventSpec{actor: "bridgeClient", event: "presentProxyCookie", file: "weaverssh_socks_proxy.go", symbol: "createX11SetupRequest", kind: "function", line: 655, tlaModule: "SSHX11WeaverSystem", tlaAction: "BridgeClientTransitions.presentProxyCookie"})
	appendRuntimeRecord(&records, repoRoot, runtimeEventSpec{actor: "bridgeServer", event: "verifyProxyCookie", file: "weaverssh_x11_server_fsm.go", symbol: "X11Server.validateAuth", kind: "method", line: 203, tlaModule: "SSHX11WeaverSystem", tlaAction: "BridgeServerTransitions.verifyProxyCookie"})
	appendRuntimeRecord(&records, repoRoot, runtimeEventSpec{actor: "bridgeServer", event: "websocketUpgradeRequested", file: "weaverssh_x11_websocket_upgrade.go", symbol: "MultiProtocolConnection.UpgradeToWebSocket", kind: "method", line: 70, tlaModule: "SSHX11ForwardWebSocketHandshake", tlaAction: "RecvValidUpgrade"})
	appendRuntimeRecord(&records, repoRoot, runtimeEventSpec{actor: "bridgeClient", event: "requestWSUpgrade", file: "weaverssh_x11_websocket_upgrade.go", symbol: "MultiProtocolConnection.UpgradeToWebSocket", kind: "method", line: 70, tlaModule: "SSHX11ForwardWebSocketHandshake", tlaAction: "RecvValidUpgrade"})
	appendRuntimeRecord(&records, repoRoot, runtimeEventSpec{actor: "bridgeServer", event: "websocketUpgradeSucceeded", file: "weaverssh_x11_websocket_upgrade.go", symbol: "ProtocolWebSocket", kind: "const", line: 21, tlaModule: "SSHX11ForwardWebSocketHandshake", tlaAction: "CompleteUpgrade"})
	appendRuntimeRecord(&records, repoRoot, runtimeEventSpec{actor: "bridgeClient", event: "wsUpgradeSucceeded", file: "weaverssh_x11_websocket_upgrade.go", symbol: "MultiProtocolConnection.UpgradeToWebSocket", kind: "method", line: 70, tlaModule: "SSHX11ForwardWebSocketHandshake", tlaAction: "CompleteUpgrade"})

	if err := writeRuntimeTrace(out, records); err != nil {
		t.Fatalf("write runtime trace: %v", err)
	}
}

func runObservedX11Setup(t *testing.T) {
	t.Helper()
	cookie := "00112233445566778899aabbccddeeff"
	server := NewX11Server(cookie)
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := &ClientConnection{conn: serverConn, state: StateListening, ctx: ctx, cancel: cancel}
	errCh := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		errCh <- server.processConnectionSetup(client)
	}()

	setup := buildObservedSetupRequest(t, cookie)
	if _, err := clientConn.Write(setup); err != nil {
		t.Fatalf("write X11 setup: %v", err)
	}
	replyHeader := make([]byte, 8)
	if _, err := io.ReadFull(clientConn, replyHeader); err != nil {
		t.Fatalf("read X11 reply header: %v", err)
	}
	if replyHeader[0] != 1 {
		t.Fatalf("X11 setup not accepted: reply[0]=%d", replyHeader[0])
	}
	bodyLen := int(binary.LittleEndian.Uint16(replyHeader[6:8])) * 4
	if bodyLen > 0 {
		if _, err := io.CopyN(io.Discard, clientConn, int64(bodyLen)); err != nil {
			t.Fatalf("drain X11 reply body: %v", err)
		}
	}
	if err := waitRuntimeErr(t, errCh, "processConnectionSetup"); err != nil {
		t.Fatalf("processConnectionSetup: %v", err)
	}
	if client.state != StateConnected || !client.authenticated {
		t.Fatalf("unexpected client state=%s authenticated=%v", client.state, client.authenticated)
	}
}

func runObservedWebSocketUpgrade(t *testing.T) {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	mpc := NewMultiProtocolConnection(serverConn)
	errCh := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		errCh <- mpc.UpgradeToWebSocket()
	}()

	request := "GET /_x11ws HTTP/1.1\r\n" +
		"Host: weaverssh\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"\r\n"
	if _, err := clientConn.Write([]byte(request)); err != nil {
		t.Fatalf("write WebSocket upgrade request: %v", err)
	}
	reader := bufio.NewReader(clientConn)
	var response strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read WebSocket response: %v", err)
		}
		response.WriteString(line)
		if line == "\r\n" {
			break
		}
	}
	if !strings.Contains(response.String(), "101 Switching Protocols") {
		t.Fatalf("missing 101 response: %q", response.String())
	}
	if err := waitRuntimeErr(t, errCh, "UpgradeToWebSocket"); err != nil {
		t.Fatalf("UpgradeToWebSocket: %v", err)
	}
	if mpc.GetProtocol() != ProtocolWebSocket {
		t.Fatalf("protocol after upgrade=%s", mpc.GetProtocol())
	}
}

func waitRuntimeErr(t *testing.T, errCh <-chan error, label string) error {
	t.Helper()
	select {
	case err := <-errCh:
		return err
	case <-time.After(3 * time.Second):
		t.Fatalf("%s timed out", label)
		return nil
	}
}

func buildObservedSetupRequest(t *testing.T, cookie string) []byte {
	t.Helper()
	cookieBytes, err := hex.DecodeString(cookie)
	if err != nil {
		t.Fatalf("decode cookie: %v", err)
	}
	authName := []byte(AuthProtoMITMagicCookie)
	namePad := (4 - (len(authName) % 4)) % 4
	dataPad := (4 - (len(cookieBytes) % 4)) % 4
	buf := make([]byte, 12+len(authName)+namePad+len(cookieBytes)+dataPad)
	buf[0] = LittleEndian
	binary.LittleEndian.PutUint16(buf[2:4], ProtocolMajorVersion)
	binary.LittleEndian.PutUint16(buf[4:6], ProtocolMinorVersion)
	binary.LittleEndian.PutUint16(buf[6:8], uint16(len(authName)))
	binary.LittleEndian.PutUint16(buf[8:10], uint16(len(cookieBytes)))
	copy(buf[12:], authName)
	copy(buf[12+len(authName)+namePad:], cookieBytes)
	return buf
}

func appendRuntimeRecord(records *[]runtimeTraceRecord, repoRoot string, spec runtimeEventSpec) {
	idx := len(*records)
	*records = append(*records, runtimeTraceRecord{
		Source:         runtimeObservedSource,
		Trace:          "goRuntimeObservedProtocolTrace",
		StepIndex:      idx,
		Actor:          spec.actor,
		Event:          spec.event,
		Arg:            nil,
		RuntimeContext: runtimeContext(spec.actor),
		TLA:            runtimeTLAAnchor{Module: spec.tlaModule, Action: spec.tlaAction},
		Implementation: runtimeImplementationAnchor{
			RepoRoot: repoRoot,
			File:     spec.file,
			Symbol:   spec.symbol,
			Kind:     spec.kind,
			Line:     spec.line,
		},
	})
}

func runtimeContext(actor string) runtimeContextRecord {
	switch actor {
	case "x11Producer":
		return runtimeContextRecord{Perspective: "userEdgeHost", FlowPlane: "x11PayloadStream", Role: "edgeX11Producer"}
	case "bridgeServer":
		return runtimeContextRecord{Perspective: "bridgeHost", FlowPlane: "websocketControl", Role: "bridgeServerProcess"}
	case "bridgeClient":
		return runtimeContextRecord{Perspective: "bridgeHost", FlowPlane: "websocketControl", Role: "bridgeClientProcess"}
	default:
		return runtimeContextRecord{}
	}
}

func writeRuntimeTrace(path string, records []runtimeTraceRecord) error {
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
