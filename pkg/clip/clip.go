// Package clip copies secrets to the system clipboard and clears them again.
//
// Copying restores whatever was on the clipboard before, so that using a
// password does not silently destroy the user's clipboard contents.
package clip

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

// ErrNoBackend reports that no clipboard tool is available.
var ErrNoBackend = errors.New("clip: no clipboard backend found")

// Backend copies text to and from a system clipboard.
type Backend interface {
	// Name identifies the backend for diagnostics.
	Name() string
	// Copy places text on the clipboard.
	Copy(ctx context.Context, text string) error
	// Paste returns the current clipboard contents.
	Paste(ctx context.Context) (string, error)
	// Available reports whether the backend can run here.
	Available() bool
}

// Detect returns the first usable clipboard backend for this session.
func Detect(selection string) (Backend, error) {
	for _, b := range backends(selection) {
		if b.Available() {
			return b, nil
		}
	}
	return nil, ErrNoBackend
}

// CopyWithTimeout puts text on the clipboard and restores the previous
// contents after d.
//
// The restore is only performed when the clipboard still holds the secret: if
// the user copied something else meanwhile, overwriting it would be worse than
// leaving the secret to be replaced naturally.
func CopyWithTimeout(ctx context.Context, b Backend, text string, d time.Duration) error {
	previous, err := b.Paste(ctx)
	if err != nil {
		// A clipboard that cannot be read is still worth writing to; the
		// restore simply becomes a clear.
		previous = ""
	}
	if err := b.Copy(ctx, text); err != nil {
		return err
	}
	if d <= 0 {
		return nil
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
	}

	current, err := b.Paste(ctx)
	if err == nil && current != text {
		return nil
	}
	return b.Copy(ctx, previous)
}

// run executes a clipboard helper, feeding it stdin and returning stdout.
func run(ctx context.Context, name string, args []string, stdin string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // the name comes from a fixed table.
	if stdin != "" {
		cmd.Stdin = stringReader(stdin)
	}
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("clip: %s: %w", name, err)
	}
	return string(out), nil
}
