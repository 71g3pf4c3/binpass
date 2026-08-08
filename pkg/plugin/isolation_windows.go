//go:build windows

package plugin

import "os/exec"

// applyIsolation is a no-op on Windows, which has no process-group equivalent
// that would help here.
func applyIsolation(_ *exec.Cmd) {}
