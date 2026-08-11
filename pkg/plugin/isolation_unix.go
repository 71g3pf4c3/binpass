//go:build !windows

package plugin

import (
	"os/exec"
	"syscall"
)

// applyIsolation applies what process-level separation the platform offers.
//
// A new process group means a plugin cannot signal binpass or its siblings
// through the shared group, and it lets binpass clean up a plugin's whole
// process tree rather than just the child it started. This is not a sandbox
// and is not claimed to be one: a level 1 plugin runs with the user's full
// authority, and only the WASM runtime changes that.
func applyIsolation(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}
