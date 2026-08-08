//go:build !windows

package storage

import "os"

// syncDir flushes a directory entry so that a rename survives a power loss.
func syncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // dir is a store path already resolved through rel.
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
