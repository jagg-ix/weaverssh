package containerstream

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeNomadRead struct {
	frame nomadExecOutput
	err   error
}

type fakeNomadWebSocket struct {
	reads chan fakeNomadRead
	done  chan struct{}
	once  sync.Once

	mu     sync.Mutex
	writes []any
	limit  int64
}

func newFakeNomadWebSocket() *fakeNomadWebSocket {
	return &fakeNomadWebSocket{reads: make(chan fakeNomadRead, 8), done: make(chan struct{})}
}

func (c *fakeNomadWebSocket) ReadJSON(target any) error {
	select {
	case <-c.done:
		return io.EOF
	case next := <-c.reads:
		if next.err != nil {
			return next.err
		}
		output, ok := target.(*nomadExecOutput)
		if !ok {
			return errors.New("unexpected read type")
		}
		*output = next.frame
		return nil
	}
}

func (c *fakeNomadWebSocket) WriteJSON(frame any) error {
	select {
	case <-c.done:
		return io.ErrClosedPipe
	default:
	}
	c.mu.Lock()
	c.writes = append(c.writes, frame)
	c.mu.Unlock()
	return nil
}

func (c *fakeNomadWebSocket) SetReadLimit(limit int64) { c.limit = limit }
func (*fakeNomadWebSocket) SetWriteDeadline(time.Time) error {
	return nil
}
func (c *fakeNomadWebSocket) Close() error {
	c.once.Do(func() { close(c.done) })
	return nil
}

func (c *fakeNomadWebSocket) capturedWrites() []any {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]any(nil), c.writes...)
}

func TestNomadNativeTTYProtocol(t *testing.T) {
	connection := newFakeNomadWebSocket()
	environment := map[string]string{
		"NOMAD_ADDR":  "https://nomad.example/proxy",
		"NOMAD_TOKEN": "agent-secret",
	}
	var dialed string
	provider := NewNomadAPIProvider(NomadAPIConfig{
		LookupEnv: func(name string) (string, bool) { value, ok := environment[name]; return value, ok },
	})
	provider.dial = func(_ context.Context, address string, _ http.Header) (nomadWebSocket, *http.Response, error) {
		dialed = address
		return connection, nil, nil
	}
	process, err := provider.StartContainerProcess(context.Background(), Request{
		TargetID: "12345678-abcd-4def-8123-123456789abc", Options: map[string]string{"namespace": "jobs", "task": "api"},
	}, ProcessSpec{Argv: []string{"/bin/sh", "-l"}, TTY: true})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(dialed)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "wss" || parsed.Path != "/proxy/v1/client/allocation/12345678-abcd-4def-8123-123456789abc/exec" || parsed.Query().Get("task") != "api" || parsed.Query().Get("namespace") != "jobs" || parsed.Query().Get("ws_handshake") != "true" {
		t.Fatalf("dialed=%s", dialed)
	}
	if parsed.Query().Get("command") != `["/bin/sh","-l"]` || parsed.Query().Get("tty") != "true" {
		t.Fatalf("query=%v", parsed.Query())
	}
	if got := process.Capabilities(); got != (ProcessCapabilities{Stdin: true, Stdout: true, TTY: true, Resize: true}) {
		t.Fatalf("capabilities=%+v", got)
	}
	if _, err := process.Stdin().Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := process.Resize(context.Background(), TerminalSize{Rows: 40, Cols: 120}); err != nil {
		t.Fatal(err)
	}
	connection.reads <- fakeNomadRead{frame: nomadExecOutput{Stdout: &nomadIOOperation{Data: []byte("ready")}}}
	connection.reads <- fakeNomadRead{frame: nomadExecOutput{Exited: true, Result: &nomadExecResult{ExitCode: 7}}}
	payload, err := io.ReadAll(process.Stdout())
	if err != nil || string(payload) != "ready" {
		t.Fatalf("stdout=%q err=%v", payload, err)
	}
	if result := process.Wait(); result.ExitCode != 7 || result.Err != nil {
		t.Fatalf("result=%+v", result)
	}
	writes := connection.capturedWrites()
	if len(writes) != 3 {
		t.Fatalf("writes=%#v", writes)
	}
	if auth, ok := writes[0].(nomadAuthFrame); !ok || auth.AuthToken != "agent-secret" || auth.Version != 1 {
		t.Fatalf("auth=%#v", writes[0])
	}
	if input, ok := writes[1].(nomadExecInput); !ok || input.Stdin == nil || string(input.Stdin.Data) != "hello" {
		t.Fatalf("stdin=%#v", writes[1])
	}
	if resize, ok := writes[2].(nomadExecInput); !ok || resize.TTYSize == nil || resize.TTYSize.Height != 40 || resize.TTYSize.Width != 120 {
		t.Fatalf("resize=%#v", writes[2])
	}
	if err := process.Signal(context.Background(), SignalINT); !errors.Is(err, ErrControlUnsupported) {
		t.Fatalf("signal err=%v", err)
	}
}

func TestNomadNativeRequiresTaskBeforeDial(t *testing.T) {
	dialed := false
	provider := NewNomadAPIProvider(NomadAPIConfig{})
	provider.dial = func(context.Context, string, http.Header) (nomadWebSocket, *http.Response, error) {
		dialed = true
		return nil, nil, errors.New("unexpected")
	}
	_, err := provider.StartContainerProcess(context.Background(), Request{TargetID: "alloc-a"}, ProcessSpec{Argv: []string{"/bin/true"}})
	if !errors.Is(err, ErrFastPathUnavailable) || dialed {
		t.Fatalf("err=%v dialed=%v", err, dialed)
	}
}

func TestNomadNativeDialFailureAllowsCLIFallback(t *testing.T) {
	provider := NewNomadAPIProvider(NomadAPIConfig{})
	provider.dial = func(context.Context, string, http.Header) (nomadWebSocket, *http.Response, error) {
		return nil, nil, errors.New("connection refused")
	}
	_, err := provider.StartContainerProcess(context.Background(), Request{TargetID: "12345678-abcd-4def-8123-123456789abc", Options: map[string]string{"task": "api"}}, ProcessSpec{Argv: []string{"/bin/true"}})
	if !errors.Is(err, ErrFastPathUnavailable) {
		t.Fatalf("err=%v", err)
	}
}

func TestNomadNativeTLSConfigurationNeverDowngrades(t *testing.T) {
	environment := map[string]string{
		"NOMAD_ADDR":        "https://nomad.example",
		"NOMAD_SKIP_VERIFY": "not-a-boolean",
	}
	provider := NewNomadAPIProvider(NomadAPIConfig{LookupEnv: func(name string) (string, bool) {
		value, ok := environment[name]
		return value, ok
	}})
	_, err := provider.StartContainerProcess(context.Background(), Request{
		TargetID: "12345678-abcd-4def-8123-123456789abc", Options: map[string]string{"task": "api"},
	}, ProcessSpec{Argv: []string{"/bin/true"}})
	if err == nil || errors.Is(err, ErrFastPathUnavailable) || !strings.Contains(err.Error(), "NOMAD_SKIP_VERIFY") {
		t.Fatalf("err=%v", err)
	}
}

func TestNomadNativeHTTPAuthorizationNeverDowngrades(t *testing.T) {
	provider := NewNomadAPIProvider(NomadAPIConfig{})
	provider.dial = func(context.Context, string, http.Header) (nomadWebSocket, *http.Response, error) {
		return nil, &http.Response{StatusCode: http.StatusForbidden, Body: io.NopCloser(strings.NewReader("permission denied"))}, errors.New("bad handshake")
	}
	_, err := provider.StartContainerProcess(context.Background(), Request{
		TargetID: "12345678-abcd-4def-8123-123456789abc", Options: map[string]string{"task": "api"},
	}, ProcessSpec{Argv: []string{"/bin/true"}})
	if err == nil || errors.Is(err, ErrFastPathUnavailable) || !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("err=%v", err)
	}
}

func TestNomadCommandEnvironmentRemainsArgv(t *testing.T) {
	provider := NewNomadAPIProvider(NomadAPIConfig{LookupEnv: func(string) (string, bool) { return "", false }})
	got, _, err := provider.execURL(Request{TargetID: "alloc-a", Options: map[string]string{"task": "api"}}, "api", []string{"env", "--", "A=1", "/bin/printf", "$A"}, false)
	if err != nil {
		t.Fatal(err)
	}
	var command []string
	if err := json.Unmarshal([]byte(got.Query().Get("command")), &command); err != nil {
		t.Fatal(err)
	}
	if want := []string{"env", "--", "A=1", "/bin/printf", "$A"}; !reflect.DeepEqual(command, want) {
		t.Fatalf("command=%#v want=%#v", command, want)
	}
}
