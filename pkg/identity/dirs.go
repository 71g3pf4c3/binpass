package identity

import (
	"os"
	"path/filepath"
	"strings"
)

// expandTilde resolves a leading "~" or "~/" to the user's home directory.
//
// A literal tilde reaches this package whenever the value was quoted in the
// shell (BINPASS_IDENTITY="~/.age/identities.age") or read from a config file:
// neither the shell nor Go expands it there, and os.ReadFile then fails with a
// baffling "no such file or directory" for a path that visibly exists. The
// CLI path is covered by internal/config's own expand, but this package reads
// BINPASS_IDENTITY and PASSAGE_IDENTITIES_FILE directly so that non-CLI
// consumers of the resolver behave the same, and pkg/ cannot import
// internal/ — hence a second, deliberately identical helper here.
func expandTilde(path string) string {
	if path == "~" || strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(path, "~"))
		}
	}
	return path
}

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
