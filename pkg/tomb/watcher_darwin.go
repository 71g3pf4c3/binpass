//go:build darwin

package tomb

import (
	"context"
	"fmt"
	"os/exec"
	"sync"
	"time"
)

// lockPollInterval is how often the screen lock state is checked.
//
// Polling rather than subscribing is a deliberate trade: the notification
// APIs are Objective-C, and reaching them means CGO, which costs the static
// cross-compiled binary the project builds everywhere else (§7.3). Two
// seconds of delay before a tomb closes is a much smaller price than that,
// and the check is a cheap read of a property the window server already
// keeps.
const lockPollInterval = 2 * time.Second

// Watcher monitors OS events for auto-close: a timer, and the screen lock.
type Watcher struct {
	// dir is the store the tomb belongs to.
	dir string
	// timer is the auto-close duration; zero disables it.
	timer time.Duration
	// onClose is called when the tomb should be closed.
	onClose func(string) error
	// closed guards against closing twice.
	closed bool
	// mu guards closed.
	mu sync.Mutex
	// cancel stops the watcher's goroutines.
	cancel context.CancelFunc
	// done is closed when the watcher has stopped.
	done chan struct{}
}

// NewWatcher starts watching for auto-close triggers.
func NewWatcher(dir string, timer time.Duration, onClose func(string) error) *Watcher {
	ctx, cancel := context.WithCancel(context.Background())
	w := &Watcher{
		dir:     dir,
		timer:   timer,
		onClose: onClose,
		cancel:  cancel,
		done:    make(chan struct{}),
	}

	go w.closeOnCancel(ctx)
	if timer > 0 {
		go w.timerLoop(ctx)
	}
	// The lock watch runs regardless of the timer: a tomb left open with no
	// timeout is exactly the one that most wants closing when the user walks
	// away and locks the screen.
	go w.lockLoop(ctx)
	return w
}

// Stop terminates the watcher.
func (w *Watcher) Stop() {
	w.cancel()
	<-w.done
}

// closeOnCancel closes done when the context is cancelled.
func (w *Watcher) closeOnCancel(ctx context.Context) {
	<-ctx.Done()
	select {
	case <-w.done:
	default:
		close(w.done)
	}
}

// triggerClose safely calls the close callback once.
func (w *Watcher) triggerClose() {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	w.closed = true
	w.mu.Unlock()

	select {
	case <-w.done:
	default:
		close(w.done)
	}

	_ = w.onClose(w.dir)
}

// timerLoop waits for the configured duration and then closes the tomb.
func (w *Watcher) timerLoop(ctx context.Context) {
	select {
	case <-time.After(w.timer):
		w.triggerClose()
	case <-ctx.Done():
	}
}

// lockLoop closes the tomb when the screen becomes locked.
func (w *Watcher) lockLoop(ctx context.Context) {
	ticker := time.NewTicker(lockPollInterval)
	defer ticker.Stop()

	// A tomb opened from a locked screen — a script, a remote session —
	// should not close itself immediately, so only a transition into the
	// locked state counts.
	wasLocked := screenLocked(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			locked := screenLocked(ctx)
			if locked && !wasLocked {
				w.triggerClose()
				return
			}
			wasLocked = locked
		}
	}
}

// screenLocked reports whether the login session's screen is locked.
//
// The state is read from the window server through ioreg rather than through
// the Objective-C notification API, which would require CGO. An error is
// reported as "not locked": failing open keeps a tomb usable on a system
// where the property cannot be read, and the timer still applies.
func screenLocked(ctx context.Context) bool {
	out, err := exec.CommandContext(ctx, "ioreg", "-n", "Root", "-d1", "-a").Output()
	if err != nil {
		return false
	}
	return parseScreenLocked(out)
}

// DoctorCheck returns a platform-specific status for binpass doctor.
func DoctorCheck() string {
	if screenLocked(context.Background()) {
		return "screen lock: detected through the window server (currently locked)"
	}
	return "screen lock: detected through the window server (currently unlocked)"
}

// FormatWatcherStatus returns a human-readable description of the watcher
// state.
func FormatWatcherStatus(timer time.Duration) string {
	if timer == 0 {
		return "auto-close: screen lock only (no timer set)"
	}
	return fmt.Sprintf("auto-close: %s timer + screen lock", timer)
}
