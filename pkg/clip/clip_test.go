package clip_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/71g3pf4c3/binpass/pkg/clip"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fake is an in-memory clipboard standing in for the system one.
type fake struct {
	// mu guards contents against the restore goroutine.
	mu sync.Mutex
	// contents is the current clipboard text.
	contents string
	// copies counts writes, to prove a restore happened.
	copies int
	// pasteErr, when set, makes reads fail.
	pasteErr error
}

func (f *fake) Name() string    { return "fake" }
func (f *fake) Available() bool { return true }

func (f *fake) Copy(_ context.Context, text string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.contents = text
	f.copies++
	return nil
}

func (f *fake) Paste(context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pasteErr != nil {
		return "", f.pasteErr
	}
	return f.contents, nil
}

// get returns the clipboard contents under lock.
func (f *fake) get() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.contents
}

func TestCopyRestoresPreviousContents(t *testing.T) {
	f := &fake{contents: "earlier work"}
	require.NoError(t, clip.CopyWithTimeout(t.Context(), f, "hunter2", 10*time.Millisecond))
	assert.Equal(t, "earlier work", f.get(), "the clipboard is handed back as it was found")
}

func TestCopyLeavesForeignContentAlone(t *testing.T) {
	f := &fake{contents: "earlier work"}

	done := make(chan error, 1)
	go func() {
		done <- clip.CopyWithTimeout(context.Background(), f, "hunter2", 60*time.Millisecond)
	}()

	// The user copies something else while the secret is on the clipboard.
	time.Sleep(20 * time.Millisecond)
	require.NoError(t, f.Copy(t.Context(), "something the user copied"))

	require.NoError(t, <-done)
	assert.Equal(t, "something the user copied", f.get(),
		"a restore must not clobber what the user copied in the meantime")
}

func TestCopyWithoutTimeoutDoesNotRestore(t *testing.T) {
	f := &fake{contents: "earlier work"}
	require.NoError(t, clip.CopyWithTimeout(t.Context(), f, "hunter2", 0))
	assert.Equal(t, "hunter2", f.get())
}

func TestCopySurvivesUnreadableClipboard(t *testing.T) {
	f := &fake{pasteErr: assert.AnError}
	err := clip.CopyWithTimeout(t.Context(), f, "hunter2", time.Millisecond)
	require.NoError(t, err, "a clipboard that cannot be read is still worth writing to")
	assert.Equal(t, "", f.get(), "with nothing to restore, the secret is cleared")
}

func TestCopyHonoursContextCancellation(t *testing.T) {
	f := &fake{contents: "earlier"}
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- clip.CopyWithTimeout(ctx, f, "hunter2", time.Hour) }()

	time.Sleep(10 * time.Millisecond)
	cancel()

	err := <-done
	assert.ErrorIs(t, err, context.Canceled)
}

func TestDetectReportsWhenNothingIsAvailable(t *testing.T) {
	// Neither session type is present in a test environment, and PATH is
	// unlikely to hold pbcopy on Linux CI.
	t.Setenv("WAYLAND_DISPLAY", "")
	t.Setenv("DISPLAY", "")
	t.Setenv("PATH", t.TempDir())

	_, err := clip.Detect("clipboard")
	assert.ErrorIs(t, err, clip.ErrNoBackend)
}
