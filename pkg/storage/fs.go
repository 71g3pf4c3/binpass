// Package storage is the on-disk layout of a password store: name-to-path
// mapping, tree walking, and durable writes.
//
// The layout is byte-identical to pass. A store is a plain directory tree, an
// entry is a file named after the entry plus a crypto extension, and nothing
// binpass-specific is ever written into it.
package storage

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ErrOutsideStore reports a name that escapes the store root.
var ErrOutsideStore = errors.New("storage: path escapes the store")

// FS is a store rooted at a directory.
type FS struct {
	// Dir is the absolute store root.
	Dir string
	// Umask masks the permissions of created files and directories,
	// honouring PASSWORD_STORE_UMASK.
	Umask os.FileMode
}

// New returns an FS rooted at dir with pass's default 077 umask.
func New(dir string) *FS {
	return &FS{Dir: filepath.Clean(dir), Umask: 0o077}
}

// Path returns the absolute path of an entry name with the given extension.
// Names are slash-separated and relative to the store root.
func (f *FS) Path(name, ext string) (string, error) {
	rel, err := f.rel(name)
	if err != nil {
		return "", err
	}
	return filepath.Join(f.Dir, rel+ext), nil
}

// DirPath returns the absolute path of a subfolder name.
func (f *FS) DirPath(name string) (string, error) {
	rel, err := f.rel(name)
	if err != nil {
		return "", err
	}
	if rel == "." {
		return f.Dir, nil
	}
	return filepath.Join(f.Dir, rel), nil
}

// rel validates an entry name and returns it as a cleaned relative path.
// Absolute names and any ".." traversal are refused: an entry name arriving
// from a plugin or a synced tree must never be able to write outside the store.
func (f *FS) rel(name string) (string, error) {
	name = strings.TrimPrefix(strings.TrimSpace(name), "/")
	if name == "" {
		return ".", nil
	}
	if filepath.IsAbs(name) {
		return "", fmt.Errorf("%w: %q", ErrOutsideStore, name)
	}
	clean := filepath.Clean(filepath.FromSlash(name))
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: %q", ErrOutsideStore, name)
	}
	return clean, nil
}

// Name converts an absolute entry path back into a store name, stripping the
// crypto extension. The result always uses forward slashes.
func (f *FS) Name(path string) (string, error) {
	rel, err := filepath.Rel(f.Dir, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("%w: %q", ErrOutsideStore, path)
	}
	rel = strings.TrimSuffix(rel, filepath.Ext(rel))
	return filepath.ToSlash(rel), nil
}

// Find returns the path of the entry called name, whatever its crypto
// extension, preferring exts in the order given. It reports fs.ErrNotExist
// when no candidate exists.
func (f *FS) Find(name string, exts []string) (string, error) {
	for _, ext := range exts {
		path, err := f.Path(name, ext)
		if err != nil {
			return "", err
		}
		if st, err := os.Stat(path); err == nil && !st.IsDir() {
			return path, nil
		}
	}
	return "", fmt.Errorf("storage: %q: %w", name, fs.ErrNotExist)
}

// IsDir reports whether name is an existing subfolder of the store.
func (f *FS) IsDir(name string) bool {
	path, err := f.DirPath(name)
	if err != nil {
		return false
	}
	st, err := os.Stat(path)
	return err == nil && st.IsDir()
}

// Entry is one secret found in the store.
type Entry struct {
	// Name is the slash-separated store name, without extension.
	Name string
	// Path is the absolute file path.
	Path string
	// Ext is the crypto extension, including the dot.
	Ext string
}

// Entries walks the subtree rooted at name and returns its entries, sorted by
// name. Dotfiles and dot-directories are skipped, matching pass, which keeps
// .git, .gpg-id and .binpass out of listings.
func (f *FS) Entries(name string, exts []string) ([]Entry, error) {
	root, err := f.DirPath(name)
	if err != nil {
		return nil, err
	}
	allowed := make(map[string]bool, len(exts))
	for _, e := range exts {
		allowed[e] = true
	}

	var out []Entry
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		base := d.Name()
		if path != root && strings.HasPrefix(base, ".") {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		ext := filepath.Ext(base)
		if !allowed[ext] {
			return nil
		}
		entryName, err := f.Name(path)
		if err != nil {
			return err
		}
		out = append(out, Entry{Name: entryName, Path: path, Ext: ext})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Read returns the raw ciphertext of a file.
func (f *FS) Read(path string) ([]byte, error) {
	return os.ReadFile(path) //nolint:gosec // paths are resolved through rel.
}

// Remove deletes an entry file and then prunes the directories it leaves
// empty, up to the store root, exactly as pass does.
func (f *FS) Remove(path string) error {
	if err := os.Remove(path); err != nil {
		return err
	}
	return f.pruneEmpty(filepath.Dir(path))
}

// pruneEmpty removes dir and its now-empty parents, stopping at the root.
func (f *FS) pruneEmpty(dir string) error {
	for dir != f.Dir && strings.HasPrefix(dir, f.Dir) {
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) > 0 {
			return nil
		}
		if err := os.Remove(dir); err != nil {
			return nil //nolint:nilerr // a directory we cannot prune is not a failure.
		}
		dir = filepath.Dir(dir)
	}
	return nil
}

// dirPerm returns the directory permissions after applying the umask.
func (f *FS) dirPerm() os.FileMode { return 0o777 &^ f.Umask }

// filePerm returns the file permissions after applying the umask.
func (f *FS) filePerm() os.FileMode { return 0o666 &^ f.Umask }
