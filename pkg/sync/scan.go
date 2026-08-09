package sync

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"lukechampine.com/blake3"
)

// Scan walks the store directory and produces a Snapshot of the current file
// states. It uses the base snapshot to optimise: files whose (Size, ModTime)
// match the base are assumed unchanged and their stored hash is reused without
// recomputing it.
//
// # Change detection
//
// The primary change detector is (Size, ModTime). If both match the base, the
// file is considered unchanged. If either differs, the hash is recomputed and
// compared. This two-step check avoids expensive hashing of the entire store
// while remaining correct: a file with unchanged (Size, ModTime) has the same
// ciphertext, because nothing wrote to it.
//
// # New files
//
// Files not present in the base are new. They receive a version vector
// initialised to {device: 1}.
//
// # Deleted files
//
// Files present in the base but not on disk are deleted. They do not appear
// in the returned snapshot. The caller should compare against the base to
// detect deletions.
func Scan(storeDir string, base Snapshot, device DeviceID, exts []string) (Snapshot, error) {
	allowed := make(map[string]bool, len(exts))
	for _, e := range exts {
		allowed[e] = true
	}

	out := make(Snapshot)
	err := filepath.WalkDir(storeDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// Skip dotfiles and dot-directories (matching pass and pkg/storage).
		name := d.Name()
		if path != storeDir && name[0] == '.' {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		ext := filepath.Ext(name)
		if !allowed[ext] {
			return nil
		}

		rel, err := filepath.Rel(storeDir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)

		info, err := d.Info()
		if err != nil {
			return err
		}

		size := info.Size()
		modTime := info.ModTime()

		// Optimisation: if (Size, ModTime) match the base, reuse the stored
		// state. The ciphertext has not changed.
		if base, ok := base[rel]; ok && base.Size == size && base.ModTime.Equal(modTime) {
			out[rel] = base
			return nil
		}

		// Compute the hash of the ciphertext.
		h, err := hashFile(path)
		if err != nil {
			return err
		}

		// If the hash matches the base despite (Size, ModTime) differing,
		// the file content is the same: metadata-only change (e.g. touch).
		if base, ok := base[rel]; ok && base.Hash == h {
			// Update the stored metadata but keep the version vector.
			updated := *base
			updated.Size = size
			updated.ModTime = modTime
			out[rel] = &updated
			return nil
		}

		// File changed or new. Build a new FileState.
		var vv VersionVector
		if base, ok := base[rel]; ok {
			// Existing file that changed: increment the local device counter.
			vv = base.Version.Increment(device, 1)
		} else {
			// New file.
			vv = VersionVector{device: 1}
		}
		out[rel] = &FileState{
			Path:    rel,
			Hash:    h,
			Size:    size,
			ModTime: modTime,
			Version: vv,
			Device:  device,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// hashFile computes the blake3 digest of the file at path.
func hashFile(path string) ([32]byte, error) {
	f, err := os.Open(path) //nolint:gosec // paths come from the store walk.
	if err != nil {
		return [32]byte{}, err
	}
	defer func() { _ = f.Close() }()

	h := blake3.New(32, nil)
	if _, err := io.Copy(h, f); err != nil {
		return [32]byte{}, err
	}
	var out [32]byte
	h.Sum(out[:0])
	return out, nil
}

// Diff returns the set of paths that changed between the base snapshot and the
// current snapshot. A path is changed if it appears in both but has a different
// hash, if it appears only in current (new), or only in base (deleted).
//
// The result is sorted by path.
func Diff(base, current Snapshot) []string {
	paths := make(map[string]struct{})
	for p := range base {
		paths[p] = struct{}{}
	}
	for p := range current {
		paths[p] = struct{}{}
	}

	var out []string
	for p := range paths {
		b, inBase := base[p]
		c, inCurrent := current[p]
		if !inBase {
			out = append(out, p) // new file
			continue
		}
		if !inCurrent {
			out = append(out, p) // deleted file
			continue
		}
		if b.Hash != c.Hash {
			out = append(out, p) // modified file
		}
	}
	sort.Strings(out)
	return out
}

// ModTime returns the modification time of path, or the zero time.
func ModTime(path string) time.Time {
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}
