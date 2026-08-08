package storage

import (
	"io"
	"os"
	"path/filepath"
)

// Write stores data at path durably: a temporary file in the same directory is
// written and fsynced, then renamed over the target, then the directory itself
// is fsynced. A crash therefore leaves either the old entry or the new one,
// never a truncated secret.
func (f *FS) Write(path string, data []byte) error {
	return f.WriteFrom(path, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
}

// WriteFrom is Write for producers that stream, so that a large binary entry
// never has to exist in memory twice.
func (f *FS) WriteFrom(path string, produce func(io.Writer) error) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, f.dirPerm()); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".binpass-tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// Any failure below must not leave a stray temporary next to the secret.
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()

	if err := tmp.Chmod(f.filePerm()); err != nil {
		return err
	}
	if err := produce(tmp); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return syncDir(dir)
}

// Rename moves an entry, creating the destination directory and pruning any
// directories the move empties.
func (f *FS) Rename(from, to string) error {
	if err := os.MkdirAll(filepath.Dir(to), f.dirPerm()); err != nil {
		return err
	}
	if err := os.Rename(from, to); err != nil {
		return err
	}
	if err := syncDir(filepath.Dir(to)); err != nil {
		return err
	}
	return f.pruneEmpty(filepath.Dir(from))
}

// MkdirAll creates a store subdirectory with the store's permissions.
func (f *FS) MkdirAll(path string) error {
	return os.MkdirAll(path, f.dirPerm())
}
