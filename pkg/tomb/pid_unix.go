//go:build linux || darwin || freebsd || netbsd || openbsd

package tomb

import (
	"syscall"
)

// pidIsDead reports whether the process with the given PID no longer exists.
// It uses syscall.Kill with signal 0, which tests process existence without
// sending a signal. os.Process.Signal(nil) returns "unsupported signal type"
// on Linux, so we use the raw syscall instead.
func pidIsDead(pid int) bool {
	err := syscall.Kill(pid, 0)
	if err == nil {
		return false
	}
	// ESRCH means the process does not exist.
	// EPERM means it exists but we lack permission.
	return err == syscall.ESRCH
}
