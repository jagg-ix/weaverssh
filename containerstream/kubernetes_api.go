package containerstream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/util/httpstream"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
)

type kubernetesStreamExecutor interface {
	StreamWithContext(context.Context, remotecommand.StreamOptions) error
}

type kubernetesExecutorFactory func(Request, []string, bool) (kubernetesStreamExecutor, error)

// kubernetesAPIProvider uses the Kubernetes exec streaming protocols directly.
// Rancher RKE and K3s share the same API contract and use a distinct provider
// name only for routing and discovery.
type kubernetesAPIProvider struct {
	name    string
	factory kubernetesExecutorFactory
}

// NewKubernetesAPIProvider creates the native API transport shared by vanilla
// Kubernetes and Rancher distributions. Name must be kubernetes or rancher.
func NewKubernetesAPIProvider(name string) (Provider, error) {
	name = normalizeProviderName(name)
	if name != ProviderKubernetes && name != ProviderRancher {
		return nil, errors.New("containerstream: Kubernetes API provider must be kubernetes or rancher")
	}
	provider := &kubernetesAPIProvider{name: name}
	provider.factory = provider.executor
	return provider, nil
}

func newKubernetesAPIProvider(name string) Provider {
	provider, err := NewKubernetesAPIProvider(name)
	if err != nil {
		panic(err)
	}
	return provider
}

func (p *kubernetesAPIProvider) Name() string { return p.name }

func (p *kubernetesAPIProvider) Discover(probe Probe) Candidate {
	if probe == nil {
		probe = OSProbe{}
	}
	candidate := Candidate{Provider: p.name}
	addEnvironment := func(name string, weight int) string {
		value, ok := probe.LookupEnv(name)
		value = strings.TrimSpace(value)
		if ok && value != "" {
			candidate.Score += weight
			candidate.Artifacts = append(candidate.Artifacts, Artifact{Kind: "environment", Value: name, Weight: weight})
			return value
		}
		return ""
	}
	configured := addEnvironment("KUBECONFIG", 30)
	inClusterHost := addEnvironment("KUBERNETES_SERVICE_HOST", 25)
	if p.name == ProviderRancher {
		addEnvironment("K3S_URL", 25)
		addEnvironment("K3S_TOKEN", 10)
	}
	files, _ := probe.(interface{ RegularFile(string) bool })
	if files != nil {
		for _, name := range filepath.SplitList(configured) {
			if name = strings.TrimSpace(name); name != "" && files.RegularFile(name) {
				candidate.Available = true
				candidate.Artifacts = append(candidate.Artifacts, Artifact{Kind: "file", Value: name, Weight: 0})
				break
			}
		}
		if !candidate.Available && inClusterHost != "" && files.RegularFile("/var/run/secrets/kubernetes.io/serviceaccount/token") {
			candidate.Available = true
		}
		if !candidate.Available && configured == "" {
			home, _ := probe.LookupEnv("HOME")
			if strings.TrimSpace(home) == "" {
				home, _ = probe.LookupEnv("USERPROFILE")
			}
			if home = strings.TrimSpace(home); home != "" {
				defaultConfig := filepath.Join(home, ".kube", "config")
				if files.RegularFile(defaultConfig) {
					candidate.Available = true
					candidate.Score += 20
					candidate.Artifacts = append(candidate.Artifacts, Artifact{Kind: "file", Value: defaultConfig, Weight: 20})
				}
			}
		}
		if p.name == ProviderRancher && files.RegularFile("/etc/rancher/k3s/k3s.yaml") {
			candidate.Available = true
			candidate.Score += 25
			candidate.Artifacts = append(candidate.Artifacts, Artifact{Kind: "file", Value: "/etc/rancher/k3s/k3s.yaml", Weight: 25})
		}
	}
	return normalizeCandidate(p.name, candidate)
}

func (p *kubernetesAPIProvider) OpenContainerStream(ctx context.Context, request Request) (io.ReadCloser, error) {
	if request.FilePath == "" || !strings.HasPrefix(request.FilePath, "/") || strings.ContainsAny(request.FilePath, "\x00\r\n") {
		return nil, errors.New("containerstream: Kubernetes API requires an absolute file path")
	}
	process, err := p.start(ctx, request, []string{"cat", "--", request.FilePath}, false, 0)
	if err != nil {
		return nil, err
	}
	_ = process.Stdin().Close()
	return newProcessFileStream(process)
}

func (p *kubernetesAPIProvider) StartContainerProcess(ctx context.Context, request Request, spec ProcessSpec) (Process, error) {
	if err := validateProcessSpec(spec); err != nil {
		return nil, err
	}
	return p.start(ctx, request, remoteArgv(spec), spec.TTY, spec.Timeout)
}

func (p *kubernetesAPIProvider) start(ctx context.Context, request Request, command []string, tty bool, timeout time.Duration) (Process, error) {
	if p == nil || p.factory == nil {
		return nil, errors.New("containerstream: Kubernetes API provider unavailable")
	}
	if _, err := safeAdapterToken("target", request.TargetID); err != nil {
		return nil, err
	}
	if err := validateKubernetesOptions(request); err != nil {
		return nil, err
	}
	executor, err := p.factory(request, command, tty)
	if err != nil {
		return nil, err
	}
	if executor == nil {
		return nil, errors.New("containerstream: Kubernetes executor factory returned nil")
	}
	return newKubernetesProcess(ctx, p.name, executor, tty, timeout), nil
}

func validateKubernetesOptions(request Request) error {
	for name, value := range request.Options {
		if name != "context" && name != "namespace" && name != "container" {
			return fmt.Errorf("containerstream: provider Kubernetes API does not support option %q", name)
		}
		if _, err := safeAdapterToken(name, value); err != nil {
			return err
		}
	}
	return nil
}

func (p *kubernetesAPIProvider) executor(request Request, command []string, tty bool) (kubernetesStreamExecutor, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if p.name == ProviderRancher && strings.TrimSpace(os.Getenv(clientcmd.RecommendedConfigPathEnvVar)) == "" {
		rules.Precedence = append([]string{"/etc/rancher/k3s/k3s.yaml"}, rules.Precedence...)
	}
	overrides := &clientcmd.ConfigOverrides{}
	overrides.CurrentContext = strings.TrimSpace(request.Options["context"])
	if namespace := strings.TrimSpace(request.Options["namespace"]); namespace != "" {
		overrides.Context.Namespace = namespace
	}
	loader := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides)
	config, err := loader.ClientConfig()
	if err != nil {
		if clientcmd.IsEmptyConfig(err) {
			return nil, fmt.Errorf("%w: Kubernetes client configuration", ErrFastPathUnavailable)
		}
		return nil, fmt.Errorf("containerstream: load Kubernetes client configuration: %w", err)
	}
	if config == nil || strings.TrimSpace(config.Host) == "" {
		return nil, fmt.Errorf("%w: Kubernetes API host", ErrFastPathUnavailable)
	}
	namespace, _, err := loader.Namespace()
	if err != nil {
		if clientcmd.IsEmptyConfig(err) {
			return nil, fmt.Errorf("%w: Kubernetes namespace", ErrFastPathUnavailable)
		}
		return nil, fmt.Errorf("containerstream: load Kubernetes namespace: %w", err)
	}
	if namespace == "" {
		namespace = "default"
	}
	execURL, err := kubernetesExecURL(config, namespace, request.TargetID, strings.TrimSpace(request.Options["container"]), command, tty)
	if err != nil {
		return nil, err
	}
	websocketExecutor, err := remotecommand.NewWebSocketExecutor(config, http.MethodGet, execURL.String())
	if err != nil {
		return nil, fmt.Errorf("containerstream: create Kubernetes WebSocket executor: %w", err)
	}
	spdyExecutor, err := remotecommand.NewSPDYExecutor(config, http.MethodPost, execURL)
	if err != nil {
		return nil, fmt.Errorf("containerstream: create Kubernetes SPDY executor: %w", err)
	}
	executor, err := remotecommand.NewFallbackExecutor(websocketExecutor, spdyExecutor, func(err error) bool {
		return httpstream.IsUpgradeFailure(err) || httpstream.IsHTTPSProxyError(err)
	})
	if err != nil {
		return nil, fmt.Errorf("containerstream: create Kubernetes streaming fallback: %w", err)
	}
	return executor, nil
}

func kubernetesExecURL(config *rest.Config, namespace, pod, container string, command []string, tty bool) (*url.URL, error) {
	base, err := url.Parse(strings.TrimSpace(config.Host))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("containerstream: invalid Kubernetes API host")
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/api/v1/namespaces/" + url.PathEscape(namespace) + "/pods/" + url.PathEscape(pod) + "/exec"
	query := base.Query()
	for _, argument := range command {
		query.Add("command", argument)
	}
	if container != "" {
		query.Set("container", container)
	}
	query.Set("stdin", "true")
	query.Set("stdout", "true")
	query.Set("stderr", fmt.Sprint(!tty))
	query.Set("tty", fmt.Sprint(tty))
	base.RawQuery = query.Encode()
	return base, nil
}

type kubernetesSizeQueue struct {
	ctx context.Context
	ch  chan remotecommand.TerminalSize
}

func (q *kubernetesSizeQueue) Next() *remotecommand.TerminalSize {
	select {
	case <-q.ctx.Done():
		return nil
	case size := <-q.ch:
		return &size
	}
}

func (q *kubernetesSizeQueue) push(size TerminalSize) {
	next := remotecommand.TerminalSize{Width: size.Cols, Height: size.Rows}
	select {
	case q.ch <- next:
		return
	default:
	}
	select {
	case <-q.ch:
	default:
	}
	select {
	case q.ch <- next:
	case <-q.ctx.Done():
	}
}

type kubernetesProcess struct {
	provider string
	tty      bool
	cancel   context.CancelFunc
	stdinW   *io.PipeWriter
	stdoutR  *io.PipeReader
	stderrR  io.ReadCloser
	resize   *kubernetesSizeQueue

	waitOnce  sync.Once
	closeOnce sync.Once
	done      chan struct{}
	streamErr chan error
	result    ProcessResult
}

func newKubernetesProcess(parent context.Context, provider string, executor kubernetesStreamExecutor, tty bool, timeout time.Duration) Process {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(parent, timeout)
	}
	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()
	var stderrR io.ReadCloser
	var stderrW *io.PipeWriter
	if tty {
		stderrR = io.NopCloser(strings.NewReader(""))
	} else {
		stderrR, stderrW = io.Pipe()
	}
	process := &kubernetesProcess{
		provider: provider, tty: tty, cancel: cancel, stdinW: stdinW, stdoutR: stdoutR, stderrR: stderrR,
		resize: &kubernetesSizeQueue{ctx: ctx, ch: make(chan remotecommand.TerminalSize, 1)},
		done:   make(chan struct{}), streamErr: make(chan error, 1),
	}
	go func() {
		options := remotecommand.StreamOptions{Stdin: stdinR, Stdout: stdoutW, Tty: tty}
		if tty {
			options.TerminalSizeQueue = process.resize
		} else {
			options.Stderr = stderrW
		}
		err := executor.StreamWithContext(ctx, options)
		_ = stdinR.CloseWithError(err)
		_ = stdoutW.Close()
		if stderrW != nil {
			_ = stderrW.Close()
		}
		process.streamErr <- err
	}()
	return process
}

func (p *kubernetesProcess) ProviderName() string { return p.provider }
func (p *kubernetesProcess) Capabilities() ProcessCapabilities {
	// Closing the remotecommand stream does not portably guarantee termination
	// of the exact exec across Kubernetes runtimes, so Terminate stays false.
	return ProcessCapabilities{Stdin: true, Stdout: true, Stderr: !p.tty, TTY: p.tty, Resize: p.tty}
}
func (p *kubernetesProcess) Stdin() io.WriteCloser { return p.stdinW }
func (p *kubernetesProcess) Stdout() io.ReadCloser { return p.stdoutR }
func (p *kubernetesProcess) Stderr() io.ReadCloser { return p.stderrR }
func (*kubernetesProcess) Signal(context.Context, ProcessSignal) error {
	return ErrControlUnsupported
}
func (p *kubernetesProcess) Resize(ctx context.Context, size TerminalSize) error {
	if !p.tty {
		return ErrControlUnsupported
	}
	if size.Rows == 0 || size.Cols == 0 {
		return errors.New("containerstream: terminal dimensions must be non-zero")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.done:
		return io.ErrClosedPipe
	default:
		p.resize.push(size)
		return nil
	}
}

func (p *kubernetesProcess) Wait() ProcessResult {
	p.waitOnce.Do(func() {
		err := <-p.streamErr
		p.result.ExitCode = 0
		if err != nil {
			p.result.ExitCode = -1
			var exitError interface{ ExitStatus() int }
			if errors.As(err, &exitError) {
				p.result.ExitCode = exitError.ExitStatus()
			} else {
				p.result.Err = err
			}
		}
		p.cancel()
		close(p.done)
	})
	<-p.done
	return p.result
}

func (p *kubernetesProcess) Close() error {
	p.closeOnce.Do(func() {
		_ = p.stdinW.Close()
		_ = p.stdoutR.Close()
		_ = p.stderrR.Close()
		p.cancel()
	})
	result := p.Wait()
	if errors.Is(result.Err, context.Canceled) {
		return nil
	}
	return result.Err
}
