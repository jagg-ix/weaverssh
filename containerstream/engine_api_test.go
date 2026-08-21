package containerstream

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
)

type engineTestRequest struct {
	method   string
	path     string
	rawQuery string
	body     []byte
}

type engineTestServer struct {
	mu            sync.Mutex
	requests      []engineTestRequest
	command       []string
	environment   []string
	stdin         []byte
	expectedStdin string
	stdout        []byte
	stderr        []byte
	exitCode      int
	tty           bool
	libpodVersion string
	createStatus  int
	startStatus   int
	holdOpen      bool
	release       chan struct{}
	releaseOnce   sync.Once
	errors        []error
}

func (s *engineTestServer) dial(context.Context, string, string) (net.Conn, error) {
	client, server := net.Pipe()
	go s.serve(server)
	return client, nil
}

func (s *engineTestServer) serve(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	request, err := http.ReadRequest(reader)
	if err != nil {
		s.recordError(err)
		return
	}
	body, err := io.ReadAll(request.Body)
	_ = request.Body.Close()
	if err != nil {
		s.recordError(err)
		return
	}
	s.mu.Lock()
	s.requests = append(s.requests, engineTestRequest{method: request.Method, path: request.URL.Path, rawQuery: request.URL.RawQuery, body: append([]byte(nil), body...)})
	s.mu.Unlock()

	switch request.URL.Path {
	case "/version":
		s.mu.Lock()
		libpodVersion := s.libpodVersion
		s.mu.Unlock()
		if libpodVersion == "" {
			libpodVersion = "5.8.2"
		}
		s.writeJSON(conn, http.StatusOK, fmt.Sprintf(`{"ApiVersion":"1.45","Components":[{"Name":"Podman Engine","Details":{"APIVersion":%q}}]}`, libpodVersion))
	case "/v1.45/containers/container-a/exec", "/v5.8.2/libpod/containers/container-a/exec":
		var create struct {
			Command     []string `json:"Cmd"`
			Environment []string `json:"Env"`
			TTY         bool     `json:"Tty"`
		}
		if err := json.Unmarshal(body, &create); err != nil {
			s.recordError(err)
			return
		}
		s.mu.Lock()
		s.command = append([]string(nil), create.Command...)
		s.environment = append([]string(nil), create.Environment...)
		s.tty = create.TTY
		status := s.createStatus
		s.mu.Unlock()
		if status == 0 {
			status = http.StatusCreated
		}
		if status != http.StatusCreated {
			s.writeJSON(conn, status, `{"message":"target denied"}`)
			return
		}
		s.writeJSON(conn, status, `{"Id":"exec-a"}`)
	case "/v1.45/exec/exec-a/start", "/v5.8.2/libpod/exec/exec-a/start":
		s.mu.Lock()
		startStatus := s.startStatus
		s.mu.Unlock()
		if startStatus == 0 {
			startStatus = http.StatusSwitchingProtocols
		}
		var response string
		if startStatus == http.StatusOK {
			response = "HTTP/1.1 200 OK\r\nContent-Type: application/vnd.docker.raw-stream\r\nConnection: close\r\n\r\n"
		} else {
			response = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n"
		}
		if _, err := io.WriteString(conn, response); err != nil {
			s.recordError(err)
			return
		}
		s.mu.Lock()
		expected := s.expectedStdin
		stdout := append([]byte(nil), s.stdout...)
		stderr := append([]byte(nil), s.stderr...)
		tty := s.tty
		s.mu.Unlock()
		stdin := make([]byte, len(expected))
		if _, err := io.ReadFull(reader, stdin); err != nil {
			s.recordError(err)
			return
		}
		s.mu.Lock()
		s.stdin = stdin
		s.mu.Unlock()
		if tty {
			if _, err := conn.Write(stdout); err != nil {
				s.recordError(err)
			}
			if s.holdOpen && s.release != nil {
				<-s.release
			}
			return
		}
		if err := writeEngineTestFrame(conn, 1, stdout); err != nil {
			s.recordError(err)
			return
		}
		if err := writeEngineTestFrame(conn, 2, stderr); err != nil {
			s.recordError(err)
		}
	case "/v1.45/exec/exec-a/json", "/v5.8.2/libpod/exec/exec-a/json":
		s.mu.Lock()
		exitCode := s.exitCode
		s.mu.Unlock()
		s.writeJSON(conn, http.StatusOK, fmt.Sprintf(`{"Running":false,"ExitCode":%d}`, exitCode))
	case "/v5.8.2/libpod/exec/exec-a/resize":
		s.writeJSON(conn, http.StatusCreated, `{}`)
	case "/v5.8.2/libpod/exec/exec-a/remove":
		var remove struct {
			Force bool `json:"Force"`
		}
		if err := json.Unmarshal(body, &remove); err != nil {
			s.recordError(err)
			return
		}
		if !remove.Force {
			s.recordError(errors.New("Libpod exec removal was not forced"))
			return
		}
		s.writeJSON(conn, http.StatusOK, `{}`)
		if s.release != nil {
			s.releaseOnce.Do(func() { close(s.release) })
		}
	default:
		s.writeJSON(conn, http.StatusNotFound, `{"message":"unexpected test route"}`)
	}
}

func (s *engineTestServer) writeJSON(writer io.Writer, status int, payload string) {
	_, err := fmt.Fprintf(writer, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", status, http.StatusText(status), len(payload), payload)
	if err != nil {
		s.recordError(err)
	}
}

func (s *engineTestServer) recordError(err error) {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) {
		return
	}
	s.mu.Lock()
	s.errors = append(s.errors, err)
	s.mu.Unlock()
}

func (s *engineTestServer) snapshot() (requests []engineTestRequest, command, environment []string, stdin []byte, serverErrors []error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	requests = append([]engineTestRequest(nil), s.requests...)
	command = append([]string(nil), s.command...)
	environment = append([]string(nil), s.environment...)
	stdin = append([]byte(nil), s.stdin...)
	serverErrors = append([]error(nil), s.errors...)
	return
}

func writeEngineTestFrame(writer io.Writer, stream byte, payload []byte) error {
	header := make([]byte, 8)
	header[0] = stream
	binary.BigEndian.PutUint32(header[4:], uint32(len(payload)))
	if _, err := writer.Write(header); err != nil {
		return err
	}
	_, err := writer.Write(payload)
	return err
}

func newEngineTestProvider(t *testing.T, server *engineTestServer, name string) *EngineAPIProvider {
	t.Helper()
	provider, err := NewEngineAPIProvider(EngineAPIConfig{
		Name:       name,
		SocketPath: "/test/engine.sock",
		Probe: &fakeProbe{
			env:     map[string]string{},
			binary:  map[string]string{},
			sockets: map[string]bool{"/test/engine.sock": true},
		},
		DialContext: server.dial,
	})
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func TestEngineAPIProcessStreamsAndInspectsExit(t *testing.T) {
	server := &engineTestServer{
		expectedStdin: "input payload",
		stdout:        []byte("standard output"),
		stderr:        []byte("standard error"),
		exitCode:      7,
	}
	provider := newEngineTestProvider(t, server, ProviderDocker)
	process, err := provider.StartContainerProcess(context.Background(), Request{TargetID: "container-a", FilePath: "/proc/exec"}, ProcessSpec{
		Argv:        []string{"/usr/bin/tool", "argument"},
		Environment: map[string]string{"BETA": "two", "ALPHA": "one"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := process.Capabilities(); got != (ProcessCapabilities{Stdin: true, Stdout: true, Stderr: true}) {
		t.Fatalf("capabilities=%+v", got)
	}
	if _, err := process.Stdin().Write([]byte(server.expectedStdin)); err != nil {
		t.Fatal(err)
	}
	if err := process.Stdin().Close(); err != nil {
		t.Fatal(err)
	}
	type readResult struct {
		payload []byte
		err     error
	}
	stdoutResult := make(chan readResult, 1)
	stderrResult := make(chan readResult, 1)
	go func() { payload, err := io.ReadAll(process.Stdout()); stdoutResult <- readResult{payload, err} }()
	go func() { payload, err := io.ReadAll(process.Stderr()); stderrResult <- readResult{payload, err} }()
	result := process.Wait()
	stdout := <-stdoutResult
	stderr := <-stderrResult
	if stdout.err != nil || stderr.err != nil {
		t.Fatalf("stdout err=%v stderr err=%v", stdout.err, stderr.err)
	}
	if string(stdout.payload) != "standard output" || string(stderr.payload) != "standard error" {
		t.Fatalf("stdout=%q stderr=%q", stdout.payload, stderr.payload)
	}
	if result.ExitCode != 7 || result.Err != nil {
		t.Fatalf("result=%+v", result)
	}
	requests, command, environment, stdin, serverErrors := server.snapshot()
	if len(serverErrors) != 0 {
		t.Fatalf("server errors=%v", serverErrors)
	}
	if !reflect.DeepEqual(command, []string{"/usr/bin/tool", "argument"}) {
		t.Fatalf("command=%q", command)
	}
	if !reflect.DeepEqual(environment, []string{"ALPHA=one", "BETA=two"}) {
		t.Fatalf("environment=%q", environment)
	}
	if string(stdin) != "input payload" {
		t.Fatalf("stdin=%q", stdin)
	}
	wantPaths := []string{"/version", "/v1.45/containers/container-a/exec", "/v1.45/exec/exec-a/start", "/v1.45/exec/exec-a/json"}
	gotPaths := make([]string, len(requests))
	for index := range requests {
		gotPaths[index] = requests[index].path
	}
	if !reflect.DeepEqual(gotPaths, wantPaths) {
		t.Fatalf("request paths=%q", gotPaths)
	}
}

func TestEngineAPIFileStreamAcceptsHTTP200RawStream(t *testing.T) {
	server := &engineTestServer{
		startStatus:   http.StatusOK,
		stdout:        []byte("file payload"),
		stderr:        []byte("diagnostic"),
		libpodVersion: "not-required-for-compatible-api",
	}
	provider := newEngineTestProvider(t, server, ProviderPodman)
	stream, err := provider.OpenContainerStream(context.Background(), Request{TargetID: "container-a", FilePath: "/var/data.bin"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if string(payload) != "file payload" {
		t.Fatalf("payload=%q", payload)
	}
	_, command, _, _, serverErrors := server.snapshot()
	if len(serverErrors) != 0 {
		t.Fatalf("server errors=%v", serverErrors)
	}
	if !reflect.DeepEqual(command, []string{"cat", "--", "/var/data.bin"}) {
		t.Fatalf("command=%q", command)
	}
}

func TestEngineAPITTYAndControlsFailClosed(t *testing.T) {
	server := &engineTestServer{}
	provider := newEngineTestProvider(t, server, ProviderDocker)
	_, err := provider.StartContainerProcess(context.Background(), Request{TargetID: "container-a", FilePath: "/proc/exec"}, ProcessSpec{
		Argv: []string{"/bin/sh"},
		TTY:  true,
	})
	if !errors.Is(err, ErrControlUnsupported) {
		t.Fatalf("TTY err=%v", err)
	}
	if requests, _, _, _, _ := server.snapshot(); len(requests) != 0 {
		t.Fatalf("TTY request reached Engine API: %+v", requests)
	}
}

func TestPodmanLibpodTTYResizeAndForcedCleanup(t *testing.T) {
	server := &engineTestServer{stdout: []byte("terminal output"), exitCode: 9}
	provider := newEngineTestProvider(t, server, ProviderPodman)
	process, err := provider.StartContainerProcess(context.Background(), Request{TargetID: "container-a", FilePath: "/proc/exec"}, ProcessSpec{
		Argv: []string{"/bin/sh"},
		TTY:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := process.Capabilities(); got != (ProcessCapabilities{Stdin: true, Stdout: true, TTY: true, Resize: true, Terminate: true}) {
		t.Fatalf("capabilities=%+v", got)
	}
	if err := process.Resize(context.Background(), TerminalSize{Rows: 40, Cols: 120}); err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(process.Stdout())
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "terminal output" {
		t.Fatalf("stdout=%q", payload)
	}
	if result := process.Wait(); result.ExitCode != 9 || result.Err != nil {
		t.Fatalf("result=%+v", result)
	}
	if err := process.Close(); err != nil {
		t.Fatal(err)
	}
	requests, command, _, _, serverErrors := server.snapshot()
	if len(serverErrors) != 0 {
		t.Fatalf("server errors=%v", serverErrors)
	}
	if !reflect.DeepEqual(command, []string{"/bin/sh"}) {
		t.Fatalf("command=%q", command)
	}
	wantPaths := []string{
		"/version",
		"/v5.8.2/libpod/containers/container-a/exec",
		"/v5.8.2/libpod/exec/exec-a/start",
		"/v5.8.2/libpod/exec/exec-a/resize",
		"/v5.8.2/libpod/exec/exec-a/json",
		"/v5.8.2/libpod/exec/exec-a/remove",
	}
	gotPaths := make([]string, len(requests))
	for index := range requests {
		gotPaths[index] = requests[index].path
	}
	if !reflect.DeepEqual(gotPaths, wantPaths) {
		t.Fatalf("request paths=%q", gotPaths)
	}
	if requests[3].rawQuery != "h=40&w=120" {
		t.Fatalf("resize query=%q", requests[3].rawQuery)
	}
}

func TestPodmanLibpodCloseForceRemovesRunningExec(t *testing.T) {
	server := &engineTestServer{holdOpen: true, release: make(chan struct{})}
	provider := newEngineTestProvider(t, server, ProviderPodman)
	process, err := provider.StartContainerProcess(context.Background(), Request{TargetID: "container-a", FilePath: "/proc/exec"}, ProcessSpec{
		Argv: []string{"/bin/sh"},
		TTY:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Close(); err != nil {
		t.Fatal(err)
	}
	requests, _, _, _, serverErrors := server.snapshot()
	if len(serverErrors) != 0 {
		t.Fatalf("server errors=%v", serverErrors)
	}
	if len(requests) != 5 || requests[3].path != "/v5.8.2/libpod/exec/exec-a/remove" || requests[4].path != "/v5.8.2/libpod/exec/exec-a/json" {
		t.Fatalf("requests=%+v", requests)
	}
}

func TestPodmanLibpodTTYRejectsVersionWithoutForcedExecRemoval(t *testing.T) {
	server := &engineTestServer{libpodVersion: "4.7.0"}
	provider := newEngineTestProvider(t, server, ProviderPodman)
	process, err := provider.StartContainerProcess(context.Background(), Request{TargetID: "container-a", FilePath: "/proc/exec"}, ProcessSpec{
		Argv: []string{"/bin/sh"},
		TTY:  true,
	})
	if process != nil || !errors.Is(err, ErrControlUnsupported) {
		t.Fatalf("process=%v err=%v", process, err)
	}
	requests, _, _, _, serverErrors := server.snapshot()
	if len(serverErrors) != 0 {
		t.Fatalf("server errors=%v", serverErrors)
	}
	if len(requests) != 1 || requests[0].path != "/version" {
		t.Fatalf("requests=%+v", requests)
	}
}

func TestEngineAPIHybridFallbackAndProtocolErrors(t *testing.T) {
	unavailable, err := NewEngineAPIProvider(EngineAPIConfig{
		Name:       ProviderDocker,
		SocketPath: "/test/missing.sock",
		Probe:      &fakeProbe{env: map[string]string{}, binary: map[string]string{}, sockets: map[string]bool{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	hybrid, err := NewHybridProvider(ProviderDocker, unavailable, staticProvider{name: "safe", payload: "fallback"})
	if err != nil {
		t.Fatal(err)
	}
	stream, err := hybrid.OpenContainerStream(context.Background(), Request{TargetID: "container-a", FilePath: "/data"})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := io.ReadAll(stream)
	if string(payload) != "fallback" {
		t.Fatalf("fallback payload=%q", payload)
	}

	server := &engineTestServer{createStatus: http.StatusNotFound}
	fast := newEngineTestProvider(t, server, ProviderDocker)
	hybrid, err = NewHybridProvider(ProviderDocker, fast, staticProvider{name: "safe", payload: "must not downgrade"})
	if err != nil {
		t.Fatal(err)
	}
	stream, err = hybrid.OpenContainerStream(context.Background(), Request{TargetID: "container-a", FilePath: "/data"})
	if stream != nil || err == nil || !strings.Contains(err.Error(), "status 404") {
		t.Fatalf("stream=%v err=%v", stream, err)
	}
}

func TestDemultiplexEngineOutputRejectsTruncatedFrame(t *testing.T) {
	var encoded strings.Builder
	header := make([]byte, 8)
	header[0] = 1
	binary.BigEndian.PutUint32(header[4:], 4)
	_, _ = encoded.Write(header)
	_, _ = encoded.WriteString("ab")
	err := demultiplexEngineOutput(strings.NewReader(encoded.String()), io.Discard, io.Discard)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("err=%v", err)
	}
}
