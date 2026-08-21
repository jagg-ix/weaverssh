package containerstream

import (
	"context"
	"errors"
	"io"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

type fakeKubernetesExecutor struct {
	stream func(context.Context, remotecommand.StreamOptions) error
}

func (e fakeKubernetesExecutor) StreamWithContext(ctx context.Context, options remotecommand.StreamOptions) error {
	return e.stream(ctx, options)
}

type fakeRemoteExitError struct{ code int }

func (e fakeRemoteExitError) Error() string   { return "remote exit" }
func (e fakeRemoteExitError) ExitStatus() int { return e.code }

func TestKubernetesExecURLUsesRepeatedArgvWithoutShell(t *testing.T) {
	got, err := kubernetesExecURL(&rest.Config{Host: "https://cluster.example/base"}, "jobs", "pod-a", "worker", []string{"/bin/printf", "%s", "a b;$HOME"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != "/base/api/v1/namespaces/jobs/pods/pod-a/exec" {
		t.Fatalf("path=%q", got.Path)
	}
	query, err := url.ParseQuery(got.RawQuery)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"/bin/printf", "%s", "a b;$HOME"}; !reflect.DeepEqual(query["command"], want) {
		t.Fatalf("command=%#v want=%#v", query["command"], want)
	}
	if query.Get("container") != "worker" || query.Get("tty") != "true" || query.Get("stderr") != "false" {
		t.Fatalf("query=%v", query)
	}
}

func TestKubernetesNativeTTYResizeAndExitStatus(t *testing.T) {
	executor := fakeKubernetesExecutor{stream: func(_ context.Context, options remotecommand.StreamOptions) error {
		if !options.Tty || options.Stdin == nil || options.Stdout == nil || options.Stderr != nil || options.TerminalSizeQueue == nil {
			return errors.New("invalid TTY stream options")
		}
		size := options.TerminalSizeQueue.Next()
		if size == nil || size.Width != 120 || size.Height != 40 {
			return errors.New("missing terminal resize")
		}
		_, _ = io.WriteString(options.Stdout, "ready")
		return fakeRemoteExitError{code: 7}
	}}
	provider := &kubernetesAPIProvider{name: ProviderKubernetes, factory: func(Request, []string, bool) (kubernetesStreamExecutor, error) {
		return executor, nil
	}}
	process, err := provider.StartContainerProcess(context.Background(), Request{TargetID: "pod-a", Options: map[string]string{"namespace": "jobs"}}, ProcessSpec{Argv: []string{"/bin/sh"}, TTY: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := process.Capabilities(); got != (ProcessCapabilities{Stdin: true, Stdout: true, TTY: true, Resize: true}) {
		t.Fatalf("capabilities=%+v", got)
	}
	if err := process.Resize(context.Background(), TerminalSize{Rows: 40, Cols: 120}); err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(process.Stdout())
	if err != nil || string(payload) != "ready" {
		t.Fatalf("stdout=%q err=%v", payload, err)
	}
	if result := process.Wait(); result.ExitCode != 7 || result.Err != nil {
		t.Fatalf("result=%+v", result)
	}
	if err := process.Signal(context.Background(), SignalINT); !errors.Is(err, ErrControlUnsupported) {
		t.Fatalf("signal err=%v", err)
	}
}

func TestKubernetesNativeNonTTYSeparatesStderr(t *testing.T) {
	executor := fakeKubernetesExecutor{stream: func(_ context.Context, options remotecommand.StreamOptions) error {
		if options.Tty || options.Stderr == nil || options.TerminalSizeQueue != nil {
			return errors.New("invalid non-TTY stream options")
		}
		var writes syncWrites
		writes.goWrite(options.Stdout, "out")
		writes.goWrite(options.Stderr, "err")
		return writes.wait()
	}}
	process := newKubernetesProcess(context.Background(), ProviderKubernetes, executor, false, 0)
	stdout := make(chan string, 1)
	stderr := make(chan string, 1)
	go func() { payload, _ := io.ReadAll(process.Stdout()); stdout <- string(payload) }()
	go func() { payload, _ := io.ReadAll(process.Stderr()); stderr <- string(payload) }()
	if result := process.Wait(); result.ExitCode != 0 || result.Err != nil {
		t.Fatalf("result=%+v", result)
	}
	if got := <-stdout; got != "out" {
		t.Fatalf("stdout=%q", got)
	}
	if got := <-stderr; got != "err" {
		t.Fatalf("stderr=%q", got)
	}
}

type syncWrites struct {
	done chan error
}

func (w *syncWrites) goWrite(destination io.Writer, payload string) {
	if w.done == nil {
		w.done = make(chan error, 2)
	}
	go func() {
		_, err := io.WriteString(destination, payload)
		w.done <- err
	}()
}

func (w *syncWrites) wait() error {
	for index := 0; index < 2; index++ {
		if err := <-w.done; err != nil && !strings.Contains(err.Error(), "closed") {
			return err
		}
	}
	return nil
}
