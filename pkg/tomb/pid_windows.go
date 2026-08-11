//go:build windows

package tomb

// pidIsDead on Windows cannot use syscall.Kill (it does not exist).
// OpenProcess + GetExitCodeProcess would be the correct approach, but for
// now we conservatively report the process as alive. This is safe: the only
// consequence is that a stale state file left by a crashed process is not
// auto-detected, and the user must run `binpass tomb close --force` or
// `binpass doctor` to clean it up.
func pidIsDead(_ int) bool {
	return false
}
