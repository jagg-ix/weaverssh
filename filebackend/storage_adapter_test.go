package filebackend

import (
	"context"
	"errors"
	"testing"

	"weaverssh/storageadapter"
)

func TestAdapterStoreBridgesCoreContract(t *testing.T) {
	adapter, err := OpenAdapterStore(context.Background(), storageadapter.Config{Engine: "memory", Namespace: "file-core"})
	if err != nil { t.Fatal(err) }
	defer adapter.Close()
	if err := adapter.Write([]BatchEntry{{Key: []byte("a"), Value: []byte("one")}, {Key: []byte("b"), Value: []byte("two")}}); err != nil { t.Fatal(err) }
	value, err := adapter.Get([]byte("a"))
	if err != nil || string(value) != "one" { t.Fatalf("value=%q err=%v", value, err) }
	if err := adapter.Delete([]byte("a")); err != nil { t.Fatal(err) }
	if _, err := adapter.Get([]byte("a")); !errors.Is(err, ErrNotFound) { t.Fatalf("err=%v", err) }
}
