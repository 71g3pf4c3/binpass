package crypto

import (
	"os"
	"sync"
)

// ttyOnce guards the single tty(1)-equivalent lookup per process.
var ttyOnce sync.Once

// cachedTTY is the controlling terminal path, empty when there is none.
var cachedTTY string

// gpgEnv returns the environment for a gpg invocation. It mirrors pass, which
// exports GPG_TTY when unset: without it a curses pinentry has no terminal to
// draw on and decryption fails on a plain console.
func gpgEnv() []string {
	env := os.Environ()
	if os.Getenv("GPG_TTY") != "" {
		return env
	}
	ttyOnce.Do(func() { cachedTTY = controllingTTY() })
	if cachedTTY == "" {
		return env
	}
	return append(env, "GPG_TTY="+cachedTTY)
}
