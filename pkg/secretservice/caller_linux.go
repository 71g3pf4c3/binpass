//go:build linux

package secretservice

import (
	"fmt"
	"os"
	"path/filepath"
)

// processExe returns the executable path of a process.
//
// This is how a caller is identified for the access policy. It is honest
// about what it proves: /proc/PID/exe names the file a process was started
// from, which a process that re-executed itself, or one whose PID has been
// reused, can misrepresent. The policy is a guard against careless and
// accidental access, not against a local attacker who is trying — and the
// D-Bus session bus, which lets any process of the user talk to any other,
// does not permit anything stronger.
func processExe(pid int) (string, error) {
	link := filepath.Join("/proc", fmt.Sprint(pid), "exe")
	exe, err := os.Readlink(link)
	if err != nil {
		return "", fmt.Errorf("secretservice: identifying pid %d: %w", pid, err)
	}
	return exe, nil
}
