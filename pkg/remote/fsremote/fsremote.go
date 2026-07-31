// Package fsremote implements the Remote interface over a plain directory
// (e.g. a shared folder, USB drive, or Dropbox path). It stores objects under
// objects/ab/cdef… and the signed manifest as manifest.json. CAS is emulated
// with a read-verify-after-write on the manifest generation, so Caps reports
// AtomicCAS=false.
package fsremote

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/71g3pf4c3/binpass/pkg/manifest"
	"github.com/71g3pf4c3/binpass/pkg/remote"
)

// manifestFile is the manifest filename within the remote root.
const manifestFile = "manifest.json"

// FS is a directory-backed Remote.
type FS struct {
	// root is the remote base directory.
	root string
}

// New returns an FS remote rooted at dir, creating it if needed.
func New(dir string) (*FS, error) {
	if err := os.MkdirAll(filepath.Join(dir, "objects"), 0o700); err != nil {
		return nil, fmt.Errorf("fsremote: mkdir: %w", err)
	}
	return &FS{root: dir}, nil
}

// Name identifies the backend.
func (f *FS) Name() string { return "fs" }

// Caps reports directory-backend capabilities.
func (f *FS) Caps() remote.Caps {
	return remote.Caps{AtomicCAS: false, History: false, Watch: false, PartialFetch: true}
}

// objectPath maps an object ID to its on-disk path (objects/ab/cdef…).
func (f *FS) objectPath(id string) (string, error) {
	hexPart := strings.TrimPrefix(id, "b3:")
	if len(hexPart) < 4 || strings.ContainsAny(hexPart, "/\\.") {
		return "", fmt.Errorf("fsremote: invalid object id %q", id)
	}
	return filepath.Join(f.root, "objects", hexPart[:2], hexPart[2:]), nil
}

// Manifest returns the current signed manifest.
func (f *FS) Manifest(_ context.Context) (*manifest.Signed, error) {
	data, err := os.ReadFile(filepath.Join(f.root, manifestFile))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, remote.ErrNotFound
		}
		return nil, fmt.Errorf("fsremote: read manifest: %w", err)
	}
	var s manifest.Signed
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("fsremote: decode manifest: %w", err)
	}
	return &s, nil
}

// CommitManifest writes m if the current remote generation equals expect.
// Concurrency is guarded by a lock file plus verify-after-write.
func (f *FS) CommitManifest(ctx context.Context, m *manifest.Signed, expect uint64) error {
	lock, err := f.acquireLock()
	if err != nil {
		return err
	}
	defer f.releaseLock(lock)

	current, err := f.currentGeneration(ctx)
	if err != nil {
		return err
	}
	if current != expect {
		return remote.ErrConflict
	}
	data, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("fsremote: encode manifest: %w", err)
	}
	return atomicWrite(filepath.Join(f.root, manifestFile), data)
}

// currentGeneration returns the generation of the stored manifest (0 if none).
func (f *FS) currentGeneration(ctx context.Context) (uint64, error) {
	s, err := f.Manifest(ctx)
	if errors.Is(err, remote.ErrNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var m manifest.Manifest
	if err := json.Unmarshal(s.Manifest, &m); err != nil {
		return 0, fmt.Errorf("fsremote: decode generation: %w", err)
	}
	return m.Generation, nil
}

// HasObjects reports which of ids exist on disk.
func (f *FS) HasObjects(_ context.Context, ids []string) (map[string]bool, error) {
	out := make(map[string]bool, len(ids))
	for _, id := range ids {
		p, err := f.objectPath(id)
		if err != nil {
			return nil, err
		}
		_, statErr := os.Stat(p)
		out[id] = statErr == nil
	}
	return out, nil
}

// PutObject writes object id from r.
func (f *FS) PutObject(_ context.Context, id string, r io.Reader) error {
	p, err := f.objectPath(id)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return fmt.Errorf("fsremote: mkdir object: %w", err)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("fsremote: read object: %w", err)
	}
	return atomicWrite(p, data)
}

// GetObject opens object id for reading.
func (f *FS) GetObject(_ context.Context, id string) (io.ReadCloser, error) {
	p, err := f.objectPath(id)
	if err != nil {
		return nil, err
	}
	fh, err := os.Open(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, remote.ErrNotFound
		}
		return nil, fmt.Errorf("fsremote: open object: %w", err)
	}
	return fh, nil
}

// DeleteObjects removes the given objects, tolerating missing files.
func (f *FS) DeleteObjects(_ context.Context, ids []string) error {
	for _, id := range ids {
		p, err := f.objectPath(id)
		if err != nil {
			return err
		}
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("fsremote: delete object: %w", err)
		}
	}
	return nil
}

// Close is a no-op for the directory backend.
func (f *FS) Close() error { return nil }
