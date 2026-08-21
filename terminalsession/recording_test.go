package terminalsession

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHashChainRecordingDetectsTampering(t *testing.T) {
	var output bytes.Buffer
	recorder, err := NewHashChainRecorder(&output)
	if err != nil {
		t.Fatal(err)
	}
	for sequence, payload := range [][]byte{[]byte("hello"), []byte("world")} {
		if err := recorder.RecordOutput(context.Background(), OutputRecord{SessionID: "session-a", Sequence: uint64(sequence + 1), Payload: payload, At: time.Unix(1, int64(sequence+1))}); err != nil {
			t.Fatal(err)
		}
	}
	var entries []RecordingEntry
	scanner := bufio.NewScanner(bytes.NewReader(output.Bytes()))
	for scanner.Scan() {
		var entry RecordingEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRecording(entries); err != nil {
		t.Fatal(err)
	}
	entries[0].PayloadBase64 = "dGFtcGVyZWQ="
	if err := VerifyRecording(entries); err == nil {
		t.Fatal("tampered recording verified")
	}
}

func TestHashChainRecordingFileVerifiesBeforeResume(t *testing.T) {
	path := filepath.Join(t.TempDir(), "terminal.ndjson")
	recorder, err := OpenHashChainRecordingFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := recorder.RecordOutput(context.Background(), OutputRecord{SessionID: "session-a", Sequence: 1, Payload: []byte("one"), At: time.Unix(1, 1)}); err != nil {
		t.Fatal(err)
	}
	if err := recorder.Close(); err != nil {
		t.Fatal(err)
	}
	recorder, err = OpenHashChainRecordingFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := recorder.RecordOutput(context.Background(), OutputRecord{SessionID: "session-a", Sequence: 2, Payload: []byte("two"), At: time.Unix(1, 2)}); err != nil {
		t.Fatal(err)
	}
	if err := recorder.Close(); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var entries []RecordingEntry
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var entry RecordingEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries=%d want=2", len(entries))
	}
	if err := VerifyRecording(entries); err != nil {
		t.Fatal(err)
	}

	entries[0].EntrySHA256 = "00"
	tampered, err := json.Marshal(entries[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(tampered, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenHashChainRecordingFile(path); err == nil {
		t.Fatal("tampered recording resumed")
	}
}
