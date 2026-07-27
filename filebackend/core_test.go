package filebackend

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCoreObservedQIDAdvancesOnMutation(t *testing.T) {
	store := NewMemoryStore()
	core, err := NewCore(store)
	if err != nil {
		t.Fatal(err)
	}
	if err := core.ObserveQID("dir/file", 42, 7); err != nil {
		t.Fatal(err)
	}
	pathID, version := core.QID("dir/file", nil)
	if pathID != 42 || version != 7 {
		t.Fatalf("qid=(%d,%d)", pathID, version)
	}
	event := Event{Operation: OperationWrite, Phase: PhaseAfter, Path: "dir/file"}
	if err := core.Record(event, "dir/file"); err != nil {
		t.Fatal(err)
	}
	pathID, version = core.QID("dir/file", nil)
	if pathID != 42 || version != 8 {
		t.Fatalf("qid after mutation=(%d,%d) want=(42,8)", pathID, version)
	}
	snapshot := core.Snapshot()
	if snapshot.Operations[OperationWrite] != 1 || snapshot.Errors != 0 {
		t.Fatalf("snapshot=%+v", snapshot)
	}
}

func TestCoreReopensPersistentStoreState(t *testing.T) {
	store := NewMemoryStore()
	first, err := NewCore(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.NextID(); err != nil {
		t.Fatal(err)
	}
	if err := first.Record(Event{Operation: OperationRead, Phase: PhaseAfter}); err != nil {
		t.Fatal(err)
	}
	second, err := NewCore(store)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := second.Snapshot()
	if snapshot.Sequence != 1 || snapshot.Operations[OperationRead] != 1 {
		t.Fatalf("snapshot=%+v", snapshot)
	}
}

func TestServiceRunsHooksAndCoreAroundBackendOperation(t *testing.T) {
	root := t.TempDir()
	backend, err := NewOSBackend(root)
	if err != nil {
		t.Fatal(err)
	}
	registry := NewRegistry(nil)
	called := false
	if err := registry.Register(Hook{
		Operation: OperationCreate, Phase: PhaseBefore, Mode: ModeEnforce,
		Handler: func(_ context.Context, event Event) error {
			called = true
			if event.Path != "created.txt" {
				t.Fatalf("event=%+v", event)
			}
			return nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	service, err := New(Config{Backend: backend, CoreStore: NewMemoryStore(), Hooks: registry})
	if err != nil {
		t.Fatal(err)
	}
	err = service.Execute(context.Background(), Event{Operation: OperationCreate, Path: "created.txt"}, []string{"created.txt"}, func(fs Backend) error {
		path, err := fs.Resolve("created.txt")
		if err != nil {
			return err
		}
		file, err := fs.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		return file.Close()
	})
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("before hook did not run")
	}
	if _, err := os.Stat(filepath.Join(root, "created.txt")); err != nil {
		t.Fatal(err)
	}
	description := service.Describe()
	if description.Core.Operations[OperationCreate] != 1 || description.Core.Sequence != 1 {
		t.Fatalf("description=%+v", description)
	}
}

func TestServiceEnforceHookPreventsMutation(t *testing.T) {
	root := t.TempDir()
	backend, err := NewOSBackend(root)
	if err != nil {
		t.Fatal(err)
	}
	registry := NewRegistry(nil)
	if err := registry.Register(Hook{
		Operation: OperationRemove, Phase: PhaseBefore, Mode: ModeEnforce,
		Handler: func(context.Context, Event) error { return errors.New("blocked") },
	}); err != nil {
		t.Fatal(err)
	}
	service, err := New(Config{Backend: backend, CoreStore: NewMemoryStore(), Hooks: registry})
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "keep.txt")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = service.Execute(context.Background(), Event{Operation: OperationRemove, Path: "keep.txt"}, []string{"keep.txt"}, func(fs Backend) error {
		return fs.Remove(target)
	})
	if err == nil {
		t.Fatal("expected hook veto")
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("file was removed despite veto: %v", err)
	}
	snapshot := service.Describe().Core
	if snapshot.Errors != 1 || snapshot.Operations[OperationRemove] != 1 {
		t.Fatalf("snapshot=%+v", snapshot)
	}
}

func TestServiceReadOnlyPreventsMutation(t *testing.T) {
	root := t.TempDir()
	backend, err := NewOSBackend(root)
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(Config{Backend: backend, CoreStore: NewMemoryStore(), ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	err = service.Execute(context.Background(), Event{Operation: OperationCreate, Path: "blocked.txt"}, []string{"blocked.txt"}, func(Backend) error {
		called = true
		return nil
	})
	if !errors.Is(err, ErrReadOnly) {
		t.Fatalf("error=%v want ErrReadOnly", err)
	}
	if called {
		t.Fatal("filesystem callback ran in read-only mode")
	}
	snapshot := service.Describe().Core
	if snapshot.Errors != 1 || snapshot.Operations[OperationCreate] != 1 {
		t.Fatalf("snapshot=%+v", snapshot)
	}
}
