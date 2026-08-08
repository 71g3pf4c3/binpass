package cli

import (
	"crypto/rand"
	"os"
	"runtime"
)

// secureTempDir returns the best place to hold a decrypted secret while it is
// being edited. On Linux /dev/shm is a tmpfs, so the plaintext never reaches a
// disk that could retain it after deletion.
func secureTempDir() string {
	if runtime.GOOS == "linux" {
		if st, err := os.Stat("/dev/shm"); err == nil && st.IsDir() {
			if f, err := os.CreateTemp("/dev/shm", ".probe-*"); err == nil {
				name := f.Name()
				_ = f.Close()
				_ = os.Remove(name)
				return "/dev/shm"
			}
		}
	}
	return ""
}

// shred overwrites a file with random bytes before removing it. On a
// journalling or copy-on-write filesystem this is best-effort, which is why
// secureTempDir prefers tmpfs in the first place.
func shred(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0o600) //nolint:gosec // path is the temporary file this process just created.
	if err != nil {
		return os.Remove(path)
	}
	if st, err := f.Stat(); err == nil && st.Size() > 0 {
		noise := make([]byte, st.Size())
		if _, err := rand.Read(noise); err == nil {
			_, _ = f.WriteAt(noise, 0)
			_ = f.Sync()
		}
	}
	_ = f.Close()
	return os.Remove(path)
}
