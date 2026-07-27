package sessionbroker

import (
	"fmt"
	"net"
	"os"
	"time"
)

// PrepareUnixSocket refuses to replace a reachable broker and removes only an
// unreachable stale filesystem entry.
func PrepareUnixSocket(path string) error {
	if _, err := os.Lstat(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	conn, err := net.DialTimeout("unix", path, 250*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		return fmt.Errorf("an active session broker already owns %s", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale broker socket %s: %w", path, err)
	}
	return nil
}
