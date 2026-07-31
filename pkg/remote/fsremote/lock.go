package fsremote

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// lockFile is the advisory lock filename within the remote root.
const lockFile = "manifest.lock"

// lockRetries bounds attempts to acquire the advisory lock.
const lockRetries = 50

// acquireLock creates an exclusive lock file, retrying briefly on contention.
// A stale lock older than staleAfter is reclaimed.
func (f *FS) acquireLock() (*os.File, error) {
	path := filepath.Join(f.root, lockFile)
	const staleAfter = 30 * time.Second

	for attempt := 0; attempt < lockRetries; attempt++ {
		fh, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			return fh, nil
		}
		if info, statErr := os.Stat(path); statErr == nil {
			if time.Since(info.ModTime()) > staleAfter {
				_ = os.Remove(path)
				continue
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return nil, fmt.Errorf("fsremote: lock timeout")
}

// releaseLock closes and removes the lock file.
func (f *FS) releaseLock(fh *os.File) {
	name := fh.Name()
	_ = fh.Close()
	_ = os.Remove(name)
}

// atomicWrite writes data to path via a temp file and rename with fsync.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("fsremote: temp: %w", err)
	}
	name := tmp.Name()
	defer os.Remove(name)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("fsremote: write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, 0o600); err != nil {
		return err
	}
	return os.Rename(name, path)
}
