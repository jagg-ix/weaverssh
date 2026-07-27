//go:build !windows

package agentbridge

import (
	"errors"
	"io"
	"net"
	"os"
	"strings"
)

// platformDefaultUpstream forwards to the standard local ssh-agent named by
// $SSH_AUTH_SOCK. WSL2 users reaching a Windows agent should instead pass
// --upstream 'exec:wv.exe agent-bridge --stdio'.
func platformDefaultUpstream() (upstream, error) {
	if sock := strings.TrimSpace(os.Getenv("SSH_AUTH_SOCK")); sock != "" {
		return upstream{
			label: "unix:" + sock,
			dial:  func() (io.ReadWriteCloser, error) { return net.Dial("unix", sock) },
		}, nil
	}
	return upstream{}, errors.New("agent-bridge: no --upstream given and SSH_AUTH_SOCK is unset")
}

// Query (Pageant WM_COPYDATA) and named pipes are Windows-only.
func Query([]byte) ([]byte, error)                { return nil, ErrUnsupported }
func dialPipe(string) (io.ReadWriteCloser, error) { return nil, ErrUnsupported }
