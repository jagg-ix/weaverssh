package p9client

import (
	"io"
	"sync"
)

// SequentialFile adapts a positional 9P File to io.Reader/io.Writer semantics.
// It keeps transfer offsets locally and does not buffer the whole file.
type SequentialFile struct {
	file   *File
	mu     sync.Mutex
	offset int64
}

// OpenReader opens path for sequential reading.
func (c *Client) OpenReader(path string) (*SequentialFile, error) {
	file, err := c.OpenFile(path, OREAD)
	if err != nil {
		return nil, err
	}
	return &SequentialFile{file: file}, nil
}

// OpenWriter opens path for sequential truncating writes, creating the file when
// it does not yet exist. The parent directory must already exist.
func (c *Client) OpenWriter(path string, perm uint32) (*SequentialFile, error) {
	file, err := c.OpenFile(path, OWRITE|OTRUNC)
	if err != nil {
		file, err = c.CreateFile(path, perm)
		if err != nil {
			return nil, err
		}
	}
	return &SequentialFile{file: file}, nil
}

// Read implements io.Reader using the current sequential offset.
func (f *SequentialFile) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if f == nil || f.file == nil {
		return 0, io.ErrClosedPipe
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	n, err := f.file.ReadAt(p, f.offset)
	f.offset += int64(n)
	if err != nil {
		return n, err
	}
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}

// Write implements io.Writer using the current sequential offset.
func (f *SequentialFile) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if f == nil || f.file == nil {
		return 0, io.ErrClosedPipe
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	n, err := f.file.WriteAt(p, f.offset)
	f.offset += int64(n)
	return n, err
}

// Close clunks the underlying 9P fid.
func (f *SequentialFile) Close() error {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.file == nil {
		return nil
	}
	err := f.file.Close()
	f.file = nil
	return err
}
