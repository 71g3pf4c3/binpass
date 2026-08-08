package remote

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"
	"time"
)

// MemRemote is an in-memory Remote implementation for testing. It stores files
// in a map and supports all Caps except Watch.
type MemRemote struct {
	mu     sync.Mutex
	name   string
	files  map[string]*memFile
	caps   Caps
	nextID int
}

type memFile struct {
	data    []byte
	rev     string
	modTime time.Time
}

// MemOptions configures a MemRemote.
type MemOptions struct {
	Name string
	Caps Caps
}

// NewMemRemote returns a new in-memory remote for testing.
func NewMemRemote(opts MemOptions) *MemRemote {
	if opts.Name == "" {
		opts.Name = "mem"
	}
	return &MemRemote{
		name:  opts.Name,
		files: make(map[string]*memFile),
		caps:  opts.Caps,
	}
}

// Name returns the remote name.
func (m *MemRemote) Name() string { return m.name }

// Caps returns the configured capabilities.
func (m *MemRemote) Caps() Caps { return m.caps }

// List returns all stored files.
func (m *MemRemote) List(_ context.Context) ([]RemoteFile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []RemoteFile
	for path, f := range m.files {
		out = append(out, RemoteFile{
			Path:    path,
			Size:    int64(len(f.data)),
			ModTime: f.modTime,
			Rev:     f.rev,
		})
	}
	return out, nil
}

// Get returns the content and revision of the file at path.
func (m *MemRemote) Get(_ context.Context, path string) (io.ReadCloser, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.files[path]
	if !ok {
		return nil, "", fmt.Errorf("remote/mem: %q not found", path)
	}
	return io.NopCloser(bytes.NewReader(f.data)), f.rev, nil
}

// Put stores content at path. If expectRev is non-empty, it must match the
// current revision.
func (m *MemRemote) Put(_ context.Context, path string, content io.Reader, expectRev string) (string, error) {
	data, err := io.ReadAll(content)
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if expectRev != "" {
		f, ok := m.files[path]
		if ok && f.rev != expectRev {
			return "", fmt.Errorf("remote/mem: conflict on %q: expected %q, got %q", path, expectRev, f.rev)
		}
	}
	m.nextID++
	rev := fmt.Sprintf("rev-%d", m.nextID)
	m.files[path] = &memFile{data: data, rev: rev, modTime: time.Now()}
	return rev, nil
}

// Delete removes the file at path.
func (m *MemRemote) Delete(_ context.Context, path string, expectRev string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.files[path]
	if !ok {
		return fmt.Errorf("remote/mem: %q not found", path)
	}
	if expectRev != "" && f.rev != expectRev {
		return fmt.Errorf("remote/mem: conflict on %q: expected %q, got %q", path, expectRev, f.rev)
	}
	delete(m.files, path)
	return nil
}

// Rename moves a file from one path to another.
func (m *MemRemote) Rename(_ context.Context, from, to string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.files[from]
	if !ok {
		return fmt.Errorf("remote/mem: %q not found", from)
	}
	delete(m.files, from)
	m.nextID++
	m.files[to] = &memFile{data: f.data, rev: fmt.Sprintf("rev-%d", m.nextID), modTime: time.Now()}
	return nil
}

// Lock returns a no-op unlock.
func (m *MemRemote) Lock(_ context.Context) (Unlock, error) {
	return NoopUnlock{}, nil
}

// Close is a no-op.
func (m *MemRemote) Close() error { return nil }
