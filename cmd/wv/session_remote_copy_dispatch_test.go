package main

import (
	"bytes"
	"testing"
)

func TestRemoteCopyInterceptorLeavesSingleRemoteFormsUnchanged(t *testing.T) {
	for _, args := range [][]string{
		{"./local.bin", "compute-node:/remote.bin"},
		{"compute-node:/remote.bin", "./local.bin"},
		{"./source.bin", "./destination.bin"},
	} {
		var stderr bytes.Buffer
		handled, code := trySessionRemoteCopy(args, &stderr)
		if handled || code != 0 || stderr.Len() != 0 {
			t.Fatalf("args=%q handled=%t code=%d stderr=%q", args, handled, code, stderr.String())
		}
	}
}
