//go:build !linux && !darwin

package tomb

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Watcher monitors OS events for auto-close. On platforms without screen
// lock detection only the timer is available; Linux uses D-Bus and macOS
// polls the window server, so this is the Windows and BSD path.
type Watcher struct {
	dir     string
	timer   time.Duration
	onClose func(string) error
	closed  bool
	mu      sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}
}

// NewWatcher starts watching for auto-close triggers. On non-Linux, only the
// timer is active.
func NewWatcher(dir string, timer time.Duration, onClose func(string) error) *Watcher {
	ctx, cancel := context.WithCancel(context.Background())
	w := &Watcher{
		dir:     dir,
		timer:   timer,
		onClose: onClose,
		cancel:  cancel,
		done:    make(chan struct{}),
	}

	// Always close done on cancel so Stop() never blocks.
	go w.closeOnCancel(ctx)

	if timer > 0 {
		go w.timerLoop(ctx)
	}
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

// DoctorCheck returns a platform-specific status for binpass doctor.
func DoctorCheck() string {
	return "screen lock auto-close: not yet implemented on this OS (timer-only)"
}

// FormatWatcherStatus returns a human-readable description of the watcher state.
func FormatWatcherStatus(timer time.Duration) string {
	if timer == 0 {
		return "auto-close: disabled (no timer set)"
	}
	return fmt.Sprintf("auto-close: %s timer (screen lock detection not yet implemented)", timer)
}
