//go:build linux

package tomb

import (
	"os"
	"path/filepath"
	"syscall"
)

// mlockDir attempts to mlock small files in the store directory. Best-effort:
// failures are silently ignored since mlock is advisory hardening.
// Only available on Linux where /dev/shm is a tmpfs and mlock is meaningful.
func mlockDir(dir string) {
	const maxMlockSize = 64 * 1024
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil || info.Size() > maxMlockSize {
			continue
		}
		path := filepath.Join(dir, e.Name())
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		fd := int(f.Fd())
		data, err := syscall.Mmap(fd, 0, int(info.Size()), syscall.PROT_READ, syscall.MAP_SHARED)
		_ = f.Close()
		if err != nil {
			continue
		}
		_ = syscall.Mlock(data)
		// The mapping will be munlocked and unmapped by the OS when the
		// process exits or the file is closed.
	}
}
