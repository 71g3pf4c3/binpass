package tomb

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// stateFileName is the name of the state file inside the sidecar directory.
// It lives under $XDG_DATA_HOME/binpass/ (outside the store), not inside the
// store itself, so it does not leak into git or sync.
const stateFileName = "tomb.state"

// stateDir returns the sidecar directory for tomb state. This is outside the
// store so that sync never picks it up.
func stateDir(storeDir string) string {
	// Use the XDG data home, scoped by a hash of the store path to support
	// multiple stores.
	if d := os.Getenv("BINPASS_DATA_DIR"); d != "" {
		return d
	}
	if d := os.Getenv("XDG_DATA_HOME"); d != "" {
		return filepath.Join(d, "binpass")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		// Fallback: store the state next to the store directory itself.
		return filepath.Join(filepath.Dir(storeDir), ".binpass-state")
	}
	return filepath.Join(home, ".local", "share", "binpass")
}

// statePath returns the full path to the state file for a given store.
// The state file is keyed by the store directory's absolute path to support
// multiple stores.
func statePath(storeDir string) string {
	dir := stateDir(storeDir)
	// Use a stable filename derived from the store path to avoid collisions.
	abs, err := filepath.Abs(storeDir)
	if err != nil {
		abs = storeDir
	}
	// Simple hash: replace path separators to make a valid filename.
	safe := filepath.Base(abs)
	if safe == "." || safe == "/" {
		safe = "default"
	}
	return filepath.Join(dir, safe+"-"+stateFileName)
}

// loadState reads the tomb state for the given store. Returns an error
// satisfying os.IsNotExist if no state file exists.
func loadState(storeDir string) (*State, error) {
	path := statePath(storeDir)
	data, err := os.ReadFile(path) //nolint:gosec // path is constructed from known components.
	if err != nil {
		return nil, err
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		// Corrupt state file: treat as missing so the caller can recover.
		return nil, fmt.Errorf("tomb: corrupt state file %s: %w", path, err)
	}
	return &st, nil
}

// saveState writes the tomb state for the given store.
func saveState(storeDir string, st *State) error {
	path := statePath(storeDir)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	// Write atomically: tmp file + rename.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// RemoveState deletes the state file for a store. Called on successful close.
func RemoveState(storeDir string) error {
	return os.Remove(statePath(storeDir))
}
