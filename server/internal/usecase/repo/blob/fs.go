// Package blob implements the usecase.BlobStore port. The fs driver stores
// ciphertext blobs on the local filesystem with atomic writes.
package blob

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// FS is a filesystem-backed BlobStore rooted at Root.
type FS struct {
	// Root is the base directory for blobs.
	Root string
}

// NewFS returns an FS rooted at root, creating it if needed.
func NewFS(root string) (*FS, error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("blob: mkdir root: %w", err)
	}
	return &FS{Root: root}, nil
}

// path resolves a storage ref to an absolute file path, guarding against
// path traversal by rejecting any ref that would escape Root.
func (f *FS) path(ref string) (string, error) {
	if strings.HasPrefix(ref, "..") || strings.Contains(ref, "../") {
		return "", fmt.Errorf("blob: invalid ref %q", ref)
	}
	joined := filepath.Join(f.Root, filepath.FromSlash(filepath.Clean("/"+ref)))
	root := filepath.Clean(f.Root)
	if joined != root && !strings.HasPrefix(joined, root+string(filepath.Separator)) {
		return "", fmt.Errorf("blob: ref escapes root %q", ref)
	}
	return joined, nil
}

// Put stores the blob under ref via a temp file and atomic rename.
func (f *FS) Put(ctx context.Context, ref string, r io.Reader) (int64, error) {
	dst, err := f.path(ref)
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return 0, fmt.Errorf("blob: mkdir: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".tmp-*")
	if err != nil {
		return 0, fmt.Errorf("blob: temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	n, err := io.Copy(tmp, r)
	if err != nil {
		tmp.Close()
		return 0, fmt.Errorf("blob: copy: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return 0, err
	}
	if err := tmp.Close(); err != nil {
		return 0, err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return 0, err
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return 0, fmt.Errorf("blob: rename: %w", err)
	}
	return n, nil
}

// Get opens the blob at ref for reading.
func (f *FS) Get(ctx context.Context, ref string) (io.ReadCloser, error) {
	dst, err := f.path(ref)
	if err != nil {
		return nil, err
	}
	fh, err := os.Open(dst)
	if err != nil {
		return nil, fmt.Errorf("blob: open: %w", err)
	}
	return fh, nil
}

// Delete removes the blob at ref, tolerating a missing file.
func (f *FS) Delete(ctx context.Context, ref string) error {
	dst, err := f.path(ref)
	if err != nil {
		return err
	}
	if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("blob: delete: %w", err)
	}
	return nil
}
