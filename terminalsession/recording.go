package terminalsession

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"weaverssh/evidencebinding"
)

const RecordingVersion = "weaverssh.terminal-recording.v1"

type RecordingEntry struct {
	Version        string `json:"version"`
	SessionID      string `json:"session_id"`
	Sequence       uint64 `json:"sequence"`
	ObservedAtUnix int64  `json:"observed_at_unix_nano"`
	PayloadBase64  string `json:"payload_base64"`
	PreviousSHA256 string `json:"previous_sha256"`
	EntrySHA256    string `json:"entry_sha256"`
}

type recordingPayload struct {
	Version        string `json:"version"`
	SessionID      string `json:"session_id"`
	Sequence       uint64 `json:"sequence"`
	ObservedAtUnix int64  `json:"observed_at_unix_nano"`
	PayloadBase64  string `json:"payload_base64"`
	PreviousSHA256 string `json:"previous_sha256"`
}

// HashChainRecorder emits replayable NDJSON whose entries commit to both the
// exact PTY bytes and the previous entry. The caller owns and secures the sink.
type HashChainRecorder struct {
	mu       sync.Mutex
	writer   io.Writer
	closer   io.Closer
	previous [sha256.Size]byte
}

func NewHashChainRecorder(writer io.Writer) (*HashChainRecorder, error) {
	if writer == nil {
		return nil, errors.New("terminalsession: recording writer is required")
	}
	return &HashChainRecorder{writer: writer}, nil
}

// OpenHashChainRecordingFile opens or resumes an owner-only NDJSON recording.
// The complete existing chain is verified before any new entry is appended.
func OpenHashChainRecordingFile(path string) (*HashChainRecorder, error) {
	path = filepath.Clean(path)
	if path == "." || path == "" {
		return nil, errors.New("terminalsession: recording path is required")
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("terminalsession: recording path must not be a symlink")
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*HashChainRecorder, error) {
		_ = file.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fail(err)
	}
	recorder := &HashChainRecorder{writer: file, closer: file}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 2*DefaultMaxFrame)
	index := 0
	for scanner.Scan() {
		var entry RecordingEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			return fail(fmt.Errorf("terminalsession: decode recording entry %d: %w", index, err))
		}
		digest, err := verifyRecordingEntry(entry, recorder.previous, index)
		if err != nil {
			return fail(err)
		}
		recorder.previous = digest
		index++
	}
	if err := scanner.Err(); err != nil {
		return fail(err)
	}
	return recorder, nil
}

func (r *HashChainRecorder) RecordOutput(_ context.Context, record OutputRecord) error {
	if r == nil || record.SessionID == "" || record.Sequence == 0 || record.At.IsZero() {
		return errors.New("terminalsession: invalid output recording")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.writer == nil {
		return errors.New("terminalsession: recording sink is closed")
	}
	payload := recordingPayload{
		Version: RecordingVersion, SessionID: record.SessionID, Sequence: record.Sequence,
		ObservedAtUnix: record.At.UnixNano(), PayloadBase64: base64.StdEncoding.EncodeToString(record.Payload),
		PreviousSHA256: hex.EncodeToString(r.previous[:]),
	}
	digest, err := recordingDigest(payload)
	if err != nil {
		return err
	}
	entry := RecordingEntry{
		Version: payload.Version, SessionID: payload.SessionID, Sequence: payload.Sequence,
		ObservedAtUnix: payload.ObservedAtUnix, PayloadBase64: payload.PayloadBase64,
		PreviousSHA256: payload.PreviousSHA256, EntrySHA256: hex.EncodeToString(digest[:]),
	}
	line, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	if err := writeFull(r.writer, line); err != nil {
		return err
	}
	r.previous = digest
	return nil
}

// VerifyRecording validates a complete recording chain without executing or
// interpreting its terminal payload.
func VerifyRecording(entries []RecordingEntry) error {
	var previous [sha256.Size]byte
	for index, entry := range entries {
		digest, err := verifyRecordingEntry(entry, previous, index)
		if err != nil {
			return err
		}
		previous = digest
	}
	return nil
}

func verifyRecordingEntry(entry RecordingEntry, previous [sha256.Size]byte, index int) ([sha256.Size]byte, error) {
	if entry.Version != RecordingVersion || entry.SessionID == "" || entry.Sequence == 0 || entry.ObservedAtUnix == 0 {
		return [sha256.Size]byte{}, fmt.Errorf("terminalsession: invalid recording entry %d", index)
	}
	if entry.PreviousSHA256 != hex.EncodeToString(previous[:]) {
		return [sha256.Size]byte{}, fmt.Errorf("terminalsession: broken recording chain at entry %d", index)
	}
	if _, err := base64.StdEncoding.DecodeString(entry.PayloadBase64); err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("terminalsession: invalid recording payload at entry %d", index)
	}
	payload := recordingPayload{
		Version: entry.Version, SessionID: entry.SessionID, Sequence: entry.Sequence,
		ObservedAtUnix: entry.ObservedAtUnix, PayloadBase64: entry.PayloadBase64,
		PreviousSHA256: entry.PreviousSHA256,
	}
	digest, err := recordingDigest(payload)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	decoded, err := hex.DecodeString(entry.EntrySHA256)
	if err != nil || len(decoded) != sha256.Size || !equalBytes(decoded, digest[:]) {
		return [sha256.Size]byte{}, fmt.Errorf("terminalsession: recording digest mismatch at entry %d", index)
	}
	return digest, nil
}

func (r *HashChainRecorder) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closer == nil {
		return nil
	}
	err := r.closer.Close()
	r.closer = nil
	r.writer = nil
	return err
}

func recordingDigest(payload recordingPayload) ([sha256.Size]byte, error) {
	canonical, err := json.Marshal(payload)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(append([]byte("weaverssh.terminal-recording.entry\x00"), canonical...)), nil
}

// MultiRecorder fans output to all configured sinks. An error is returned if
// any sink fails, allowing RecordingRequired to fail closed.
type MultiRecorder []Recorder

func (recorders MultiRecorder) RecordOutput(ctx context.Context, record OutputRecord) error {
	var failures []error
	for _, recorder := range recorders {
		if recorder != nil {
			if err := recorder.RecordOutput(ctx, record); err != nil {
				failures = append(failures, err)
			}
		}
	}
	return errors.Join(failures...)
}

// EvidenceRecorder records only output digests and sizes in the signed agent
// journal. Raw terminal content remains confined to explicit playback sinks.
type EvidenceRecorder struct {
	Journal *evidencebinding.AgentEvidenceJournal
}

func (r EvidenceRecorder) RecordOutput(ctx context.Context, record OutputRecord) error {
	if r.Journal == nil {
		return errors.New("terminalsession: evidence journal unavailable")
	}
	digest := sha256.Sum256(record.Payload)
	_, err := r.Journal.Record(ctx, "terminal.output", record.SessionID, map[string]string{
		"sequence":       strconv.FormatUint(record.Sequence, 10),
		"bytes":          strconv.Itoa(len(record.Payload)),
		"payload_sha256": hex.EncodeToString(digest[:]),
	})
	return err
}

// JournalObserver makes lifecycle transitions independently verifiable without
// placing resume tokens or terminal bytes in evidence details.
type JournalObserver struct {
	Journal *evidencebinding.AgentEvidenceJournal
}

func (o JournalObserver) Observe(ctx context.Context, transition Transition) error {
	if o.Journal == nil {
		return errors.New("terminalsession: evidence journal unavailable")
	}
	_, err := o.Journal.Record(ctx, "terminal.transition", transition.SessionID, map[string]string{
		"from": string(transition.From), "to": string(transition.To), "reason": transition.Reason,
	})
	return err
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}
