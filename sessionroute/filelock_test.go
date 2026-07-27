package sessionroute

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

const routeLockHelperEnv = "WEAVERSSH_TEST_ROUTE_LOCK_HELPER"

func TestAcquireLockIgnoresStaleSentinelContents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.lock")
	if err := os.WriteFile(path, []byte("999999\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	unlock, err := acquireLock(context.Background(), path, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("acquire stale sentinel: %v", err)
	}
	unlock()
}

func TestAcquireLockSerializesAndReleases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.lock")
	unlockFirst, err := acquireLock(context.Background(), path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if _, err := acquireLock(ctx, path, 30*time.Millisecond); !errors.Is(err, ErrRegistryBusy) && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("contended acquire error=%v", err)
	}
	unlockFirst()
	unlockSecond, err := acquireLock(context.Background(), path, time.Second)
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	unlockSecond()
}

func TestAcquireLockReleasedWhenProcessExits(t *testing.T) {
	if path := os.Getenv(routeLockHelperEnv); path != "" {
		if _, err := acquireLock(context.Background(), path, time.Second); err != nil {
			os.Exit(2)
		}
		// Deliberately skip the returned unlock closure. The process exit must
		// release the operating-system lock.
		os.Exit(0)
	}

	path := filepath.Join(t.TempDir(), "routes.lock")
	command := exec.Command(os.Args[0], "-test.run=^TestAcquireLockReleasedWhenProcessExits$")
	command.Env = append(os.Environ(), routeLockHelperEnv+"="+path)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("lock helper: %v output=%s", err, output)
	}
	unlock, err := acquireLock(context.Background(), path, time.Second)
	if err != nil {
		t.Fatalf("acquire after helper exit: %v", err)
	}
	unlock()
}
