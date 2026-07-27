package sessionbroker

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

const (
	// EnvSocket overrides the Unix socket recorded in the active state file.
	EnvSocket = "WEAVERSSH_SESSION_SOCKET"
	// EnvState overrides the active session state-file path.
	EnvState = "WEAVERSSH_SESSION_STATE"
)

// ReadState reads and validates one attach-process state file.
func ReadState(path string) (State, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return State{}, err
	}
	var state State
	if err := json.Unmarshal(payload, &state); err != nil {
		return State{}, fmt.Errorf("sessionbroker: decode state: %w", err)
	}
	if state.Version != protocolVersion {
		return State{}, fmt.Errorf("sessionbroker: unsupported state version %q", state.Version)
	}
	state.Socket = strings.TrimSpace(state.Socket)
	state.Binding = strings.TrimSpace(state.Binding)
	state.Node = strings.TrimSpace(state.Node)
	if state.PID <= 0 || state.Socket == "" || state.Binding == "" || state.Node == "" || state.StartedAt.IsZero() {
		return State{}, errors.New("sessionbroker: incomplete active-session state")
	}
	return state, nil
}

// ActiveState resolves the per-user state file and optional environment
// overrides used by broker-aware wv commands.
func ActiveState() (State, error) {
	_, defaultState, err := DefaultPaths()
	if err != nil {
		return State{}, err
	}
	statePath := strings.TrimSpace(os.Getenv(EnvState))
	if statePath == "" {
		statePath = defaultState
	}
	state, err := ReadState(statePath)
	if err != nil {
		return State{}, fmt.Errorf("sessionbroker: no active session at %s: %w", statePath, err)
	}
	if socket := strings.TrimSpace(os.Getenv(EnvSocket)); socket != "" {
		state.Socket = socket
	}
	return state, nil
}
