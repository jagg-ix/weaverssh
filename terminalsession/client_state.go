package terminalsession

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	ClientStateVersion  = "weaverssh.terminal-client-state.v1"
	MaxClientStateBytes = 64 << 10
)

// ClientState contains the identity-bound secondary resume secret. It must be
// stored owner-only and never printed by status or JSON inspection commands.
type ClientState struct {
	Version      string    `json:"version"`
	Node         string    `json:"node"`
	SessionID    string    `json:"session_id"`
	ResumeToken  string    `json:"resume_token,omitempty"`
	LastSequence uint64    `json:"last_sequence,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Terminated   bool      `json:"terminated,omitempty"`
	ExitCode     *int      `json:"exit_code,omitempty"`
}

func (s ClientState) Validate() error {
	if s.Version != ClientStateVersion || !nodeNamePattern.MatchString(strings.TrimSpace(s.Node)) || strings.TrimSpace(s.SessionID) == "" || s.CreatedAt.IsZero() || s.UpdatedAt.IsZero() {
		return errors.New("terminalsession: invalid client state")
	}
	if s.Terminated {
		if s.ResumeToken != "" {
			return errors.New("terminalsession: terminated client state retains a resume token")
		}
	} else if strings.TrimSpace(s.ResumeToken) == "" {
		return errors.New("terminalsession: resumable client state has no token")
	}
	return nil
}

func SaveClientState(path string, state ClientState) error {
	if err := state.Validate(); err != nil {
		return err
	}
	absolute, err := filepath.Abs(filepath.Clean(strings.TrimSpace(path)))
	if err != nil || absolute == "" {
		return errors.New("terminalsession: invalid client state path")
	}
	directory := filepath.Dir(absolute)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(absolute); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("terminalsession: client state path must not be a symlink")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	file, err := os.OpenFile(absolute, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	fail := func(err error) error {
		_ = file.Close()
		return err
	}
	if err := os.Chmod(absolute, 0o600); err != nil {
		return fail(err)
	}
	encoder := json.NewEncoder(file)
	if err := encoder.Encode(state); err != nil {
		return fail(err)
	}
	if err := file.Sync(); err != nil {
		return fail(err)
	}
	return file.Close()
}

func LoadClientState(path string) (ClientState, error) {
	absolute, err := filepath.Abs(filepath.Clean(strings.TrimSpace(path)))
	if err != nil || absolute == "" {
		return ClientState{}, errors.New("terminalsession: invalid client state path")
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return ClientState{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return ClientState{}, errors.New("terminalsession: client state must be a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return ClientState{}, fmt.Errorf("terminalsession: client state permissions %o expose its resume token", info.Mode().Perm())
	}
	file, err := os.Open(absolute)
	if err != nil {
		return ClientState{}, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, MaxClientStateBytes+1))
	if err != nil {
		return ClientState{}, err
	}
	if len(data) == 0 || len(data) > MaxClientStateBytes {
		return ClientState{}, errors.New("terminalsession: invalid client state size")
	}
	var state ClientState
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return ClientState{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ClientState{}, errors.New("terminalsession: trailing client state data")
	}
	if err := state.Validate(); err != nil {
		return ClientState{}, err
	}
	return state, nil
}
