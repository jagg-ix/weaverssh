// Package sessionresume provides explicit resumable operations across dynamic
// transport generations. It is intentionally offset-based: callers must supply
// idempotent ReaderAt/WriterAt endpoints. Arbitrary byte streams are not replayed.
package sessionresume

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"
)

type ReaderAtCloser interface { ReadAt([]byte, int64) (int, error); Close() error }
type WriterAtCloser interface { WriteAt([]byte, int64) (int, error); Close() error }
type OpenReader func(context.Context) (ReaderAtCloser, error)
type OpenWriter func(context.Context) (WriterAtCloser, error)
type RetryFunc func(error) bool
type CheckpointFunc func(Checkpoint)

type Checkpoint struct {
	Offset int64 `json:"offset"`
	Size int64 `json:"size"`
	Attempts int `json:"attempts"`
	GenerationOpens int `json:"generation_opens"`
}

type CopyConfig struct {
	Size int64
	ChunkBytes int
	MaxAttempts int
	MinRetryDelay time.Duration
	MaxRetryDelay time.Duration
	Retry RetryFunc
	Checkpoint CheckpointFunc
}

type Result struct { Bytes int64 `json:"bytes"`; Attempts int `json:"attempts"`; GenerationOpens int `json:"generation_opens"` }

func Copy(ctx context.Context, openReader OpenReader, openWriter OpenWriter, config CopyConfig) (Result, error) {
	if ctx == nil { ctx = context.Background() }
	if openReader == nil || openWriter == nil || config.Size < 0 { return Result{}, errors.New("sessionresume: invalid copy configuration") }
	if config.ChunkBytes <= 0 { config.ChunkBytes = 256 << 10 }
	if config.ChunkBytes > 4<<20 { return Result{}, errors.New("sessionresume: chunk exceeds 4 MiB") }
	if config.MaxAttempts <= 0 { config.MaxAttempts = 12 }
	if config.MinRetryDelay <= 0 { config.MinRetryDelay = 100 * time.Millisecond }
	if config.MaxRetryDelay <= 0 { config.MaxRetryDelay = 3 * time.Second }
	if config.Retry == nil { config.Retry = func(error) bool { return true } }
	if config.Size == 0 { return Result{}, nil }

	var reader ReaderAtCloser
	var writer WriterAtCloser
	closeEndpoints := func() { if reader != nil { _ = reader.Close(); reader = nil }; if writer != nil { _ = writer.Close(); writer = nil } }
	defer closeEndpoints()
	result := Result{}
	buffer := make([]byte, config.ChunkBytes)
	offset := int64(0)
	delay := config.MinRetryDelay
	attemptsAtOffset := 0

	open := func() error {
		closeEndpoints()
		var err error
		reader, err = openReader(ctx)
		if err != nil { return fmt.Errorf("open reader: %w", err) }
		writer, err = openWriter(ctx)
		if err != nil { _ = reader.Close(); reader = nil; return fmt.Errorf("open writer: %w", err) }
		result.GenerationOpens++
		return nil
	}
	for offset < config.Size {
		if err := ctx.Err(); err != nil { return result, err }
		if reader == nil || writer == nil {
			if err := open(); err != nil {
				result.Attempts++; attemptsAtOffset++
				if !config.Retry(err) || attemptsAtOffset >= config.MaxAttempts { return result, err }
				if err := waitRetry(ctx, delay); err != nil { return result, err }
				delay = nextDelay(delay, config.MaxRetryDelay)
				continue
			}
		}
		base := offset
		want := int64(len(buffer)); if remaining := config.Size - base; remaining < want { want = remaining }
		n, readErr := reader.ReadAt(buffer[:want], base)
		if n > 0 {
			written := 0
			for written < n {
				count, writeErr := writer.WriteAt(buffer[written:n], base+int64(written))
				if count > 0 {
					written += count
					offset = base + int64(written)
					result.Bytes += int64(count)
					attemptsAtOffset = 0
					delay = config.MinRetryDelay
					if config.Checkpoint != nil { config.Checkpoint(Checkpoint{Offset: offset, Size: config.Size, Attempts: result.Attempts, GenerationOpens: result.GenerationOpens}) }
				}
				if writeErr != nil {
					result.Attempts++; attemptsAtOffset++; closeEndpoints()
					if !config.Retry(writeErr) || attemptsAtOffset >= config.MaxAttempts { return result, fmt.Errorf("write at %d: %w", offset, writeErr) }
					if err := waitRetry(ctx, delay); err != nil { return result, err }
					delay = nextDelay(delay, config.MaxRetryDelay)
					break
				}
				if count == 0 { return result, io.ErrNoProgress }
			}
			if written < n { continue }
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			result.Attempts++; attemptsAtOffset++; closeEndpoints()
			if !config.Retry(readErr) || attemptsAtOffset >= config.MaxAttempts { return result, fmt.Errorf("read at %d: %w", offset, readErr) }
			if err := waitRetry(ctx, delay); err != nil { return result, err }
			delay = nextDelay(delay, config.MaxRetryDelay)
			continue
		}
		if n == 0 {
			if errors.Is(readErr, io.EOF) { return result, fmt.Errorf("sessionresume: source ended at %d before declared size %d", offset, config.Size) }
			return result, io.ErrNoProgress
		}
	}
	return result, nil
}

func waitRetry(ctx context.Context, delay time.Duration) error { timer := time.NewTimer(delay); defer timer.Stop(); select { case <-timer.C: return nil; case <-ctx.Done(): return ctx.Err() } }
func nextDelay(current, maximum time.Duration) time.Duration { next := current * 2; if next > maximum { return maximum }; return next }
