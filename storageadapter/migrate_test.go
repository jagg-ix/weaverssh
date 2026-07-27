package storageadapter

import (
	"context"
	"errors"
	"testing"
)

func TestMigrateBetweenEngines(t *testing.T) {
	source, err := Open(context.Background(), Config{Engine: "memory", Namespace: "source"})
	if err != nil { t.Fatal(err) }
	defer source.Close()
	destination, err := Open(context.Background(), Config{Engine: "memory", Namespace: "destination"})
	if err != nil { t.Fatal(err) }
	defer destination.Close()
	if err := source.Update(context.Background(), func(tx Tx) error {
		if err := tx.Put([]byte("keep/1"), []byte("one")); err != nil { return err }
		if err := tx.Put([]byte("keep/2"), []byte("two")); err != nil { return err }
		return tx.Put([]byte("skip/1"), []byte("other"))
	}); err != nil { t.Fatal(err) }
	report, err := Migrate(context.Background(), source, destination, MigrateOptions{Prefix: []byte("keep/"), BatchSize: 1})
	if err != nil || report.Entries != 2 || report.Batches != 2 { t.Fatalf("report=%+v err=%v", report, err) }
	if _, err := destination.Get(context.Background(), []byte("skip/1")); !errors.Is(err, ErrNotFound) { t.Fatalf("err=%v", err) }
	if _, err := Migrate(context.Background(), source, destination, MigrateOptions{Prefix: []byte("keep/"), BatchSize: 2}); !errors.Is(err, ErrConflict) { t.Fatalf("err=%v", err) }
}
