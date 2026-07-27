package sessionbroker

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	hopStateVersion = "weaverssh.hop-state.v1"
	maxHopStateSize = 64 << 10
)

// HopState persists the already-verified recursive path beside the active
// session state so another local shell can start the next recursive session-host.
type HopState struct {
	Version      string `json:"version"`
	PreviousNode string `json:"previous_node"`
	HopChain     string `json:"hop_chain"`
	Depth        int    `json:"depth"`
}

// HopStatePath returns the user-private sidecar for one active state file.
func HopStatePath(statePath string) string {
	return strings.TrimSpace(statePath) + ".hop"
}

// WriteHopState atomically stores verified recursive metadata with mode 0600.
func WriteHopState(statePath string, state HopState) error {
	statePath = strings.TrimSpace(statePath)
	if statePath == "" {
		return errors.New("sessionbroker: empty state path for hop metadata")
	}
	state.Version = hopStateVersion
	state.PreviousNode = strings.TrimSpace(state.PreviousNode)
	state.HopChain = strings.TrimSpace(state.HopChain)
	if state.PreviousNode == "" || state.HopChain == "" || state.Depth <= 0 || len(state.HopChain) > maxHopStateSize {
		return errors.New("sessionbroker: incomplete recursive hop state")
	}
	payload, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	path := HopStatePath(statePath)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".hop-state-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	ok := false
	defer func() {
		_ = temp.Close()
		if !ok {
			_ = os.Remove(tempName)
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temp.Write(payload); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempName, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// ReadHopState reads one verified-hop sidecar.
func ReadHopState(statePath string) (HopState, error) {
	path := HopStatePath(statePath)
	payload, err := os.ReadFile(path)
	if err != nil {
		return HopState{}, err
	}
	if len(payload) > maxHopStateSize {
		return HopState{}, errors.New("sessionbroker: recursive hop state is too large")
	}
	var state HopState
	if err := json.Unmarshal(payload, &state); err != nil {
		return HopState{}, fmt.Errorf("sessionbroker: decode recursive hop state: %w", err)
	}
	state.PreviousNode = strings.TrimSpace(state.PreviousNode)
	state.HopChain = strings.TrimSpace(state.HopChain)
	if state.Version != hopStateVersion || state.PreviousNode == "" || state.HopChain == "" || state.Depth <= 0 {
		return HopState{}, errors.New("sessionbroker: invalid recursive hop state")
	}
	return state, nil
}

// ActiveHopState resolves the active state-file path and reads its sidecar.
func ActiveHopState() (HopState, error) {
	_, defaultState, err := DefaultPaths()
	if err != nil {
		return HopState{}, err
	}
	statePath := strings.TrimSpace(os.Getenv(EnvState))
	if statePath == "" {
		statePath = defaultState
	}
	state, err := ReadHopState(statePath)
	if err != nil {
		return HopState{}, fmt.Errorf("sessionbroker: no recursive hop state at %s: %w", HopStatePath(statePath), err)
	}
	return state, nil
}

// RemoveHopState removes the recursive sidecar for one state file.
func RemoveHopState(statePath string) error {
	err := os.Remove(HopStatePath(statePath))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
