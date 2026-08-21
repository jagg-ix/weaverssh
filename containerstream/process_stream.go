package containerstream

import (
	"errors"
	"fmt"
	"io"
	"sync"
)

// processFileStream adapts a process-backed `cat` to the read-only Provider
// contract. Stderr is drained concurrently so a diagnostic cannot deadlock the
// stdout stream.
type processFileStream struct {
	process    Process
	stdout     io.ReadCloser
	stderr     *boundedWriter
	stderrDone chan struct{}

	mu      sync.Mutex
	done    bool
	waitErr error
}

func newProcessFileStream(process Process) (io.ReadCloser, error) {
	if process == nil || process.Stdout() == nil {
		if process != nil {
			_ = process.Close()
		}
		return nil, errors.New("containerstream: process stream has no stdout")
	}
	stream := &processFileStream{
		process: process, stdout: process.Stdout(),
		stderr: &boundedWriter{maximum: maxCommandStderr}, stderrDone: make(chan struct{}),
	}
	if process.Stderr() == nil {
		close(stream.stderrDone)
	} else {
		go func() {
			_, _ = io.Copy(stream.stderr, process.Stderr())
			close(stream.stderrDone)
		}()
	}
	return stream, nil
}

func (s *processFileStream) Read(payload []byte) (int, error) {
	n, err := s.stdout.Read(payload)
	if !errors.Is(err, io.EOF) {
		return n, err
	}
	if waitErr := s.wait(false); waitErr != nil {
		return n, waitErr
	}
	return n, io.EOF
}

func (s *processFileStream) Close() error {
	_ = s.stdout.Close()
	return s.wait(true)
}

func (s *processFileStream) wait(cancel bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		return s.waitErr
	}
	if cancel {
		_ = s.process.Close()
	}
	result := s.process.Wait()
	<-s.stderrDone
	s.waitErr = result.Err
	if s.waitErr == nil && result.ExitCode != 0 {
		s.waitErr = fmt.Errorf("containerstream: %s file stream exited with code %d", s.process.ProviderName(), result.ExitCode)
		if detail := s.stderr.String(); detail != "" {
			s.waitErr = fmt.Errorf("%w: %s", s.waitErr, detail)
		}
	}
	if cancel {
		s.waitErr = nil
	}
	s.done = true
	return s.waitErr
}
