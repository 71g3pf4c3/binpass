//go:build !windows

package crypto

import "os"

// controllingTTY returns the path of the terminal attached to stdin, or an
// empty string when stdin is not a terminal.
func controllingTTY() string {
	st, err := os.Stdin.Stat()
	if err != nil || st.Mode()&os.ModeCharDevice == 0 {
		return ""
	}
	// /dev/tty always names the controlling terminal of the process and needs
	// no readlink dance across platforms.
	if _, err := os.Stat("/dev/tty"); err != nil {
		return ""
	}
	return "/dev/tty"
}
