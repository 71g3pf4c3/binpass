package sync

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"lukechampine.com/blake3"
)

// FsckResult describes a single inconsistency found by Fsck.
type FsckResult struct {
	// Path is the store-relative file path.
	Path string
	// Issue describes the problem.
	Issue string
	// Severity is "error" or "warning".
	Severity string
}

// Fsck checks the consistency of the password store against the state
// database. It compares the files on disk with the entries in state.db and
// reports any inconsistencies:
//
//   - Files on disk that are not in state.db (untracked).
//   - Files in state.db that are not on disk (orphaned state).
//   - Files whose size or hash differs from state.db (drift).
//   - state.db location inside the password store (critical leak risk).
//   - Missing .gpg-id or .age-recipients files.
func Fsck(storeDir, stateDir string, db *StateDB) ([]FsckResult, error) {
	var results []FsckResult

	// Check state.db is not inside the store.
	if err := CheckStateLocation(stateDir, storeDir); err != nil {
		results = append(results, FsckResult{
			Path:     "state.db",
			Issue:    err.Error(),
			Severity: "error",
		})
	}

	// Scan the disk.
	diskFiles, err := scanDisk(storeDir)
	if err != nil {
		return nil, fmt.Errorf("fsck: scan disk: %w", err)
	}

	// Load state.db entries.
	base, err := db.LoadBase()
	if err != nil {
		return nil, fmt.Errorf("fsck: load base: %w", err)
	}

	// Cross-reference: disk vs state.
	for path, info := range diskFiles {
		state, inState := base[path]
		if !inState {
			results = append(results, FsckResult{
				Path:     path,
				Issue:    "file on disk but not in state.db (untracked)",
				Severity: "warning",
			})
			continue
		}
		if info.size != state.Size {
			results = append(results, FsckResult{
				Path:     path,
				Issue:    fmt.Sprintf("size drift: disk=%d, state=%d", info.size, state.Size),
				Severity: "warning",
			})
		}
		// Hash check: if the state has a non-zero hash, compare with the
		// on-disk hash. This detects content changes that did not change the
		// file size (e.g. a partial write or corruption).
		if state.Hash != [32]byte{} && info.hash != [32]byte{} && info.hash != state.Hash {
			results = append(results, FsckResult{
				Path:     path,
				Issue:    "hash drift: file content differs from state.db",
				Severity: "warning",
			})
		}
	}

	// Cross-reference: state vs disk (orphaned entries).
	for path, state := range base {
		if _, onDisk := diskFiles[path]; !onDisk {
			results = append(results, FsckResult{
				Path:     path,
				Issue:    fmt.Sprintf("in state.db but not on disk (orphaned, last seen %s)", state.ModTime.Format("2006-01-02")),
				Severity: "warning",
			})
			// Check if there's a conflict file for this orphaned entry.
			baseName := path[:len(path)-len(filepath.Ext(path))]
			conflictPrefix := baseName + ".conflict-" + string(state.Device)
			for diskPath := range diskFiles {
				if strings.HasPrefix(diskPath, conflictPrefix) {
					results = append(results, FsckResult{
						Path:     diskPath,
						Issue:    "conflict file found for orphaned entry",
						Severity: "warning",
					})
				}
			}
		}
	}

	// Check for missing recipient files.
	if _, err := os.Stat(filepath.Join(storeDir, ".gpg-id")); err != nil {
		if _, err := os.Stat(filepath.Join(storeDir, ".age-recipients")); err != nil {
			// Neither exists: only a warning if there are encrypted files.
			if len(diskFiles) > 0 {
				results = append(results, FsckResult{
					Path:     ".gpg-id / .age-recipients",
					Issue:    "no recipient file found; store may not be properly initialised",
					Severity: "warning",
				})
			}
		}
	}

	return results, nil
}

// diskEntry is a simplified file info for the disk scan.
type diskEntry struct {
	size int64
	hash [32]byte
}

// scanDisk walks the store directory and returns all .gpg and .age files
// with their size and blake3 hash.
func scanDisk(storeDir string) (map[string]*diskEntry, error) {
	files := make(map[string]*diskEntry)
	err := filepath.WalkDir(storeDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(storeDir, path)
		if err != nil {
			return nil
		}
		// Skip dotfiles.
		if strings.HasPrefix(rel, ".") {
			return nil
		}
		// Only crypto files.
		ext := filepath.Ext(rel)
		if ext != ".gpg" && ext != ".age" {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		entry := &diskEntry{size: info.Size()}
		// Hash the file contents. We read the file here because WalkDir
		// gives us a DirEntry, not the content. For large stores this is
		// I/O-heavy, but fsck is an explicit operator command, not a
		// hot path.
		data, err := os.ReadFile(path) //nolint:gosec // path is store-relative.
		if err == nil {
			entry.hash = blake3.Sum256(data)
		}
		files[rel] = entry
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}
