package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"weaverssh/evidencebinding"
)

const (
	AgentEmbeddedImmuDBPathEnv     = "WEAVERSSH_AGENT_IMMUDB_PATH"
	AgentEmbeddedImmuDBProviderEnv = "WEAVERSSH_AGENT_IMMUDB_PROVIDER"
	AgentEmbeddedImmuDBStreamEnv   = "WEAVERSSH_AGENT_EVIDENCE_STREAM"
)

// AgentEmbeddedImmuDBConfig enables an in-process immudb evidence store and a
// durable signed event journal for a WeaverSSH agent runtime.
type AgentEmbeddedImmuDBConfig struct {
	Path         string
	ProviderName string
	StreamID     string
}

func AgentEmbeddedImmuDBConfigFromEnv(getenv func(string) string) AgentEmbeddedImmuDBConfig {
	if getenv == nil {
		getenv = os.Getenv
	}
	return AgentEmbeddedImmuDBConfig{
		Path:         strings.TrimSpace(getenv(AgentEmbeddedImmuDBPathEnv)),
		ProviderName: strings.TrimSpace(getenv(AgentEmbeddedImmuDBProviderEnv)),
		StreamID:     strings.TrimSpace(getenv(AgentEmbeddedImmuDBStreamEnv)),
	}
}

func (c AgentEmbeddedImmuDBConfig) Validate() error {
	if strings.TrimSpace(c.Path) == "" {
		return fmt.Errorf("embedded agent evidence requires %s or an explicit path", AgentEmbeddedImmuDBPathEnv)
	}
	return nil
}

// AgentRuntimeWithEmbeddedImmuDB couples the normal agent runtime with a local
// embedded immudb anchor provider and an append-only signed event journal.
type AgentRuntimeWithEmbeddedImmuDB struct {
	*AgentRuntime
	provider evidencebinding.NamedAnchorProvider
	journal  *evidencebinding.AgentEvidenceJournal
	closeOnce sync.Once
	closeErr  error
}

func NewAgentRuntimeWithEmbeddedImmuDB(config AgentConfig, authCookie string, embedded AgentEmbeddedImmuDBConfig) (*AgentRuntimeWithEmbeddedImmuDB, error) {
	if err := embedded.Validate(); err != nil {
		return nil, err
	}
	runtime, err := NewAgentRuntime(config, authCookie)
	if err != nil {
		return nil, err
	}
	root, err := filepath.Abs(filepath.Clean(strings.TrimSpace(embedded.Path)))
	if err != nil {
		_ = runtime.Close()
		return nil, err
	}
	anchor, err := evidencebinding.OpenEmbeddedImmuDBAnchor(filepath.Join(root, "store"))
	if err != nil {
		_ = runtime.Close()
		return nil, err
	}
	providerName := strings.TrimSpace(embedded.ProviderName)
	if providerName == "" {
		providerName = "agent-embedded-immudb"
	}
	provider := evidencebinding.NamedAnchorProvider{ProviderName: providerName, Inner: anchor}
	streamID := strings.TrimSpace(embedded.StreamID)
	if streamID == "" {
		streamID = "agent/" + providerName
	}
	journal, err := evidencebinding.OpenAgentEvidenceJournal(context.Background(), evidencebinding.AgentJournalConfig{
		Directory: filepath.Join(root, "journal"),
		StreamID:  streamID,
	}, provider)
	if err != nil {
		_ = provider.Close()
		_ = runtime.Close()
		return nil, err
	}
	wrapped := &AgentRuntimeWithEmbeddedImmuDB{AgentRuntime: runtime, provider: provider, journal: journal}
	wrapped.recordEvidence("runtime.initialized", streamID, map[string]string{
		"interface": string(runtime.InterfaceMode()),
		"provider":  providerName,
	})
	return wrapped, nil
}

func (r *AgentRuntimeWithEmbeddedImmuDB) EvidenceProvider() evidencebinding.AnchorProvider {
	if r == nil || r.AgentRuntime == nil {
		return nil
	}
	return r.provider
}

func (r *AgentRuntimeWithEmbeddedImmuDB) EvidenceJournal() *evidencebinding.AgentEvidenceJournal {
	if r == nil {
		return nil
	}
	return r.journal
}

func (r *AgentRuntimeWithEmbeddedImmuDB) EvidenceStatus() evidencebinding.AgentJournalStatus {
	if r == nil || r.journal == nil {
		return evidencebinding.AgentJournalStatus{Version: evidencebinding.AgentJournalVersion}
	}
	return r.journal.Status()
}

func (r *AgentRuntimeWithEmbeddedImmuDB) VerifyEvidenceJournal(ctx context.Context) (evidencebinding.VerificationReport, error) {
	if r == nil || r.journal == nil {
		return evidencebinding.VerificationReport{}, evidencebinding.ErrInvalidEvidence
	}
	return r.journal.Verify(ctx)
}

func (r *AgentRuntimeWithEmbeddedImmuDB) ExportEvidenceJournal() evidencebinding.AgentJournalExport {
	if r == nil || r.journal == nil {
		return evidencebinding.AgentJournalExport{Version: evidencebinding.AgentJournalVersion}
	}
	return r.journal.Export()
}

func (r *AgentRuntimeWithEmbeddedImmuDB) AnchorEvidenceHead(ctx context.Context, head evidencebinding.Head) (evidencebinding.AnchorReceipt, error) {
	if r == nil || r.AgentRuntime == nil {
		return evidencebinding.AnchorReceipt{}, evidencebinding.ErrInvalidAnchor
	}
	return r.provider.Anchor(ctx, head)
}

func (r *AgentRuntimeWithEmbeddedImmuDB) VerifyEvidenceReceipt(ctx context.Context, head evidencebinding.Head, receipt evidencebinding.AnchorReceipt) error {
	if r == nil || r.AgentRuntime == nil {
		return evidencebinding.ErrInvalidAnchor
	}
	return r.provider.Verify(ctx, head, receipt)
}

// ListenAndServe mirrors AgentRuntime.ListenAndServe while ensuring that the
// listener lifecycle and accepted transports are committed to the journal.
func (r *AgentRuntimeWithEmbeddedImmuDB) ListenAndServe() error {
	if r == nil || r.AgentRuntime == nil {
		return errors.New("embedded evidence agent runtime is nil")
	}
	if r.InterfaceMode() == AgentInterfaceLibrary {
		return fmt.Errorf("library interface does not open a listener; call ServeConn with an in-process connection")
	}
	listener, cleanupListener, err := listenAgent(r.Config())
	if err != nil {
		r.recordEvidence("listener.failed", r.EvidenceStatus().StreamID, map[string]string{"error": err.Error()})
		return err
	}
	defer cleanupListener()
	defer listener.Close()
	r.recordEvidence("listener.started", r.EvidenceStatus().StreamID, map[string]string{
		"network": r.Config().ListenNetwork,
		"address": listener.Addr().String(),
	})
	return r.ServeListener(listener)
}

func (r *AgentRuntimeWithEmbeddedImmuDB) ServeListener(listener net.Listener) error {
	if listener == nil {
		return errors.New("embedded evidence agent listener is nil")
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				r.recordEvidence("listener.closed", r.EvidenceStatus().StreamID, nil)
				return nil
			}
			r.recordEvidence("connection.accept_failed", r.EvidenceStatus().StreamID, map[string]string{"error": err.Error()})
			continue
		}
		go r.ServeConn(conn)
	}
}

func (r *AgentRuntimeWithEmbeddedImmuDB) ServeConn(conn net.Conn) {
	if conn == nil {
		return
	}
	subject := r.EvidenceStatus().StreamID
	details := map[string]string{"network": conn.LocalAddr().Network()}
	if remote := conn.RemoteAddr(); remote != nil {
		details["remote"] = remote.String()
	}
	r.recordEvidence("connection.accepted", subject, details)
	defer r.recordEvidence("connection.closed", subject, details)
	r.AgentRuntime.ServeConn(conn)
}

func (r *AgentRuntimeWithEmbeddedImmuDB) recordEvidence(kind, subject string, details map[string]string) {
	if r == nil || r.journal == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := r.journal.Record(ctx, kind, subject, details); err != nil {
		log.Printf("agent evidence journal %s: %v", kind, err)
	}
}

func (r *AgentRuntimeWithEmbeddedImmuDB) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		r.recordEvidence("runtime.stopping", r.EvidenceStatus().StreamID, nil)
		var errs []error
		if r.journal != nil {
			if err := r.journal.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		if err := r.provider.Close(); err != nil {
			errs = append(errs, err)
		}
		if r.AgentRuntime != nil {
			if err := r.AgentRuntime.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		r.closeErr = errors.Join(errs...)
	})
	return r.closeErr
}
