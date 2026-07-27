package sessionresume

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

type memoryReader struct{ data []byte }
func (r *memoryReader) ReadAt(p []byte, off int64) (int, error) { if off >= int64(len(r.data)) { return 0, io.EOF }; n := copy(p, r.data[off:]); if int(off)+n >= len(r.data) { return n, io.EOF }; return n, nil }
func (*memoryReader) Close() error { return nil }

type sharedWriter struct {
	mu sync.Mutex
	data []byte
	failOnce bool
	failed bool
}
func (w *sharedWriter) open() *writerHandle { return &writerHandle{shared: w} }
type writerHandle struct{ shared *sharedWriter }
func (w *writerHandle) WriteAt(p []byte, off int64) (int, error) {
	w.shared.mu.Lock(); defer w.shared.mu.Unlock()
	if int(off)+len(p) > len(w.shared.data) { w.shared.data = append(w.shared.data, make([]byte, int(off)+len(p)-len(w.shared.data))...) }
	if w.shared.failOnce && !w.shared.failed && len(p) > 7 {
		copy(w.shared.data[off:], p[:7]); w.shared.failed = true; return 7, errors.New("injected transport loss")
	}
	copy(w.shared.data[off:], p); return len(p), nil
}
func (*writerHandle) Close() error { return nil }

func TestCopyResumesAfterPartialWrite(t *testing.T) {
	source := bytes.Repeat([]byte("resumable-payload-"), 10000)
	writer := &sharedWriter{failOnce: true}
	readerOpens := 0
	writerOpens := 0
	var checkpoints []Checkpoint
	result, err := Copy(context.Background(), func(context.Context) (ReaderAtCloser, error) {
		readerOpens++; return &memoryReader{data: source}, nil
	}, func(context.Context) (WriterAtCloser, error) {
		writerOpens++; return writer.open(), nil
	}, CopyConfig{Size: int64(len(source)), ChunkBytes: 4096, MinRetryDelay: time.Millisecond, MaxRetryDelay: time.Millisecond, Checkpoint: func(c Checkpoint) { checkpoints = append(checkpoints, c) }})
	if err != nil { t.Fatal(err) }
	if !bytes.Equal(writer.data, source) { t.Fatalf("copied bytes differ: got=%d want=%d", len(writer.data), len(source)) }
	if result.Bytes != int64(len(source)) || result.Attempts != 1 || result.GenerationOpens < 2 { t.Fatalf("result=%+v", result) }
	if readerOpens < 2 || writerOpens < 2 { t.Fatalf("opens reader=%d writer=%d", readerOpens, writerOpens) }
	if len(checkpoints) == 0 || checkpoints[len(checkpoints)-1].Offset != int64(len(source)) { t.Fatalf("last checkpoint=%+v", checkpoints) }
}

func TestCopyRejectsEarlyEOF(t *testing.T) {
	_, err := Copy(context.Background(), func(context.Context) (ReaderAtCloser, error) { return &memoryReader{data: []byte("short")}, nil }, func(context.Context) (WriterAtCloser, error) { return (&sharedWriter{}).open(), nil }, CopyConfig{Size: 100, MaxAttempts: 1})
	if err == nil { t.Fatal("expected early EOF") }
}

func TestCopyStopsOnContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background()); cancel()
	_, err := Copy(ctx, func(context.Context) (ReaderAtCloser, error) { return &memoryReader{data: []byte("data")}, nil }, func(context.Context) (WriterAtCloser, error) { return (&sharedWriter{}).open(), nil }, CopyConfig{Size: 4})
	if !errors.Is(err, context.Canceled) { t.Fatalf("error=%v", err) }
}
