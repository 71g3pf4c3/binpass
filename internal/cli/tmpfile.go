package cli

import (
	"crypto/rand"
	"os"
	"os/signal"
	"runtime"
	"syscall"
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

// shredOnSignal shreds path when the process is interrupted or terminated,
// and returns the function that disarms the handler.
//
// A deferred shred covers a normal return and a panic unwind, but not a
// signal: the default disposition of SIGINT and SIGTERM kills the process
// before any defer runs. That is the ordinary way out of an edit — Ctrl-C in
// $EDITOR goes to the whole foreground process group, binpass included — so
// without this the decrypted entry stayed behind in the temporary file with
// nothing left to remove it.
//
// The handler exits rather than returning: the editor received the same
// signal, the edit is over, and destroying the plaintext is all binpass has
// left to do.
func shredOnSignal(path string) (stop func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	done := make(chan struct{})

	go func() {
		select {
		case sig := <-ch:
			_ = shred(path)
			// What a shell reports for a signalled child, so that a script
			// wrapping binpass still sees an interrupted edit as one.
			code := 130
			if sig == syscall.SIGTERM {
				code = 143
			}
			os.Exit(code)
		case <-done:
		}
	}()

	return func() {
		signal.Stop(ch)
		close(done)
	}
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
