package identity

import (
	"os"
	"path/filepath"
)

// dataDir returns $XDG_DATA_HOME/binpass, the sidecar directory holding state
// that must never end up inside the store itself.
func dataDir() string {
	if d := os.Getenv("BINPASS_DATA_DIR"); d != "" {
		return d
	}
	if d := os.Getenv("XDG_DATA_HOME"); d != "" {
		return filepath.Join(d, "binpass")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".local", "share", "binpass")
}

// configDir returns the user's XDG config directory.
func configDir() string {
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config")
}
