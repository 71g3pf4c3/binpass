//go:build linux

package tomb

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
)

// Watcher monitors OS events (screen lock, suspend) and fires a callback
// when the tomb should be auto-closed. It also manages a timer-based auto-close.
//
// On Linux, it listens to:
//   - org.freedesktop.login1: PrepareForSleep (suspend/resume)
//   - org.freedesktop.ScreenSaver: ActiveChanged (screen lock/unlock, KDE)
//   - org.gnome.ScreenSaver: ActiveChanged (GNOME)
//
// The D-Bus connection is session-bus for screensaver signals and system-bus
// for login1. If D-Bus is unavailable (headless, container), only the timer
// is active.
type Watcher struct {
	// dir is the store directory being watched.
	dir string
	// timer is the auto-close duration; zero means no timer.
	timer time.Duration
	// onClose is called when the tomb should be auto-closed.
	onClose func(dir string) error
	// closed reports whether the tomb has been closed (prevents double-close).
	closed bool
	// mu guards closed.
	mu sync.Mutex
	// closeDone closes the done channel exactly once. A select on the
	// channel followed by close() is not atomic: two goroutines can both
	// find it open and both close it, which panics.
	closeDone sync.Once
	// cancel shuts down the D-Bus listeners and the done-closer.
	cancel context.CancelFunc
	// done is closed when the watcher has fully stopped.
	done chan struct{}
}

// NewWatcher starts watching for auto-close triggers. It returns immediately;
// the actual monitoring runs in background goroutines.
func NewWatcher(dir string, timer time.Duration, onClose func(string) error) *Watcher {
	ctx, cancel := context.WithCancel(context.Background())
	w := &Watcher{
		dir:     dir,
		timer:   timer,
		onClose: onClose,
		cancel:  cancel,
		done:    make(chan struct{}),
	}

	// Always start a closer that signals done when the context is cancelled.
	// This ensures Stop() unblocks even when there is no timer.
	go w.closeOnCancel(ctx)

	// Start timer-based auto-close.
	if timer > 0 {
		go w.timerLoop(ctx)
	}

	// Start D-Bus-based screen lock / suspend monitoring.
	go w.dbusLoop(ctx)

	return w
}

// closeOnCancel waits for ctx to be cancelled and closes the done channel.
// This is the primary mechanism to ensure Stop() always returns.
func (w *Watcher) closeOnCancel(ctx context.Context) {
	<-ctx.Done()
	w.closeDone.Do(func() { close(w.done) })
}

// Stop terminates the watcher. It is safe to call after the tomb has been
// closed (the callback will not fire after Stop returns).
func (w *Watcher) Stop() {
	w.cancel()
	<-w.done
}

// triggerClose safely calls the close callback once and closes the done
// channel to unblock Stop().
func (w *Watcher) triggerClose() {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	w.closed = true
	w.mu.Unlock()

	// Signal that the watcher is done before calling the potentially
	// blocking close callback.
	w.closeDone.Do(func() { close(w.done) })

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

// dbusLoop connects to the session and system buses and subscribes to screen
// lock and suspend signals. If the connection fails, the watcher degrades
// gracefully to timer-only.
func (w *Watcher) dbusLoop(ctx context.Context) {
	// Session bus: screensaver signals.
	go w.watchSessionBus(ctx)
	// System bus: suspend/resume.
	go w.watchSystemBus(ctx)
}

// watchSessionBus connects to the D-Bus session bus and watches for
// screensaver ActiveChanged signals.
func (w *Watcher) watchSessionBus(ctx context.Context) {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		// No session bus (headless, container): degrade to timer-only.
		return
	}
	defer func() { _ = conn.Close() }()

	// GNOME screensaver.
	_ = conn.BusObject().Call("org.freedesktop.DBus.AddMatch", 0,
		"type='signal',path='/org/gnome/ScreenSaver',interface='org.gnome.ScreenSaver',member='ActiveChanged'").Store()

	// KDE / freedesktop screensaver.
	_ = conn.BusObject().Call("org.freedesktop.DBus.AddMatch", 0,
		"type='signal',path='/org/freedesktop/ScreenSaver',interface='org.freedesktop.ScreenSaver',member='ActiveChanged'").Store()

	ch := make(chan *dbus.Signal, 16)
	conn.Signal(ch)

	for {
		select {
		case sig := <-ch:
			if len(sig.Body) < 1 {
				continue
			}
			locked, ok := sig.Body[0].(bool)
			if !ok || !locked {
				continue
			}
			// Screen locked: close the tomb.
			w.triggerClose()
			return
		case <-ctx.Done():
			return
		}
	}
}

// watchSystemBus connects to the D-Bus system bus and watches for
// PrepareForSleep from logind.
func (w *Watcher) watchSystemBus(ctx context.Context) {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()

	// logind: PrepareForSleep(bool). true = about to sleep, false = just woke.
	_ = conn.BusObject().Call("org.freedesktop.DBus.AddMatch", 0,
		"type='signal',path='/org/freedesktop/login1',interface='org.freedesktop.login1.Manager',member='PrepareForSleep'").Store()

	ch := make(chan *dbus.Signal, 16)
	conn.Signal(ch)

	for {
		select {
		case sig := <-ch:
			if len(sig.Body) < 1 {
				continue
			}
			sleeping, ok := sig.Body[0].(bool)
			if !ok || !sleeping {
				continue
			}
			// About to sleep: close the tomb now.
			w.triggerClose()
			return
		case <-ctx.Done():
			return
		}
	}
}

// DoctorCheck inspects the D-Bus session for screen lock capability. Returns
// a human-readable status for binpass doctor.
func DoctorCheck() string {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return "D-Bus session bus unavailable (timer-only auto-close)"
	}
	defer func() { _ = conn.Close() }()

	// Check for GNOME screensaver.
	gnome := false
	if err := conn.Object("org.gnome.ScreenSaver", "/org/gnome/ScreenSaver").Call("org.freedesktop.DBus.Introspectable.Introspect", 0).Store(nil); err == nil {
		gnome = true
	}

	// Check for freedesktop screensaver.
	fd := false
	if err := conn.Object("org.freedesktop.ScreenSaver", "/org/freedesktop/ScreenSaver").Call("org.freedesktop.DBus.Introspectable.Introspect", 0).Store(nil); err == nil {
		fd = true
	}

	// Check for logind.
	sysConn, err := dbus.ConnectSystemBus()
	if err == nil {
		defer func() { _ = sysConn.Close() }()
	}

	result := "D-Bus: "
	if gnome {
		result += "GNOME screensaver, "
	}
	if fd {
		result += "freedesktop screensaver, "
	}
	if sysConn != nil {
		result += "logind suspend"
	}
	if !gnome && !fd {
		result += "no screensaver detected (timer-only auto-close)"
	}
	return result
}

// FormatWatcherStatus returns a human-readable description of the watcher
// state for binpass tomb status.
func FormatWatcherStatus(timer time.Duration) string {
	if timer == 0 {
		return "auto-close: disabled (no timer set)"
	}
	return fmt.Sprintf("auto-close: %s timer + D-Bus screen lock/suspend", timer)
}
