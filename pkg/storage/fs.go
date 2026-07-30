// Package storage manages the on-disk password-store tree: atomic writes,
// directory traversal, and hierarchical .age-recipients resolution.
package storage

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// recipientsFile is the per-directory recipients list filename.
const recipientsFile = ".age-recipients"

// Ext is the ciphertext file extension used by binpass.
const Ext = ".age"

// FS is a filesystem-backed password store rooted at Dir.
type FS struct {
	// Dir is the absolute root of the store.
	Dir string
}

// New returns an FS rooted at dir.
func New(dir string) *FS {
	return &FS{Dir: dir}
}

// path resolves a logical secret name to its ciphertext file path.
func (f *FS) path(name string) string {
	return filepath.Join(f.Dir, filepath.FromSlash(name)+Ext)
}

// Exists reports whether a secret with name exists.
func (f *FS) Exists(name string) bool {
	_, err := os.Stat(f.path(name))
	return err == nil
}

// Read returns the raw ciphertext bytes for name.
func (f *FS) Read(name string) ([]byte, error) {
	data, err := os.ReadFile(f.path(name))
	if err != nil {
		return nil, fmt.Errorf("storage: read %s: %w", name, err)
	}
	return data, nil
}

// Write atomically stores ciphertext for name (0600 file, 0700 dirs).
func (f *FS) Write(name string, data []byte) error {
	dst := f.path(name)
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return fmt.Errorf("storage: mkdir: %w", err)
	}
	return atomicWrite(dst, data, 0o600)
}

// Remove deletes the secret and prunes now-empty parent directories.
func (f *FS) Remove(name string) error {
	dst := f.path(name)
	if err := os.Remove(dst); err != nil {
		return fmt.Errorf("storage: remove %s: %w", name, err)
	}
	f.pruneEmpty(filepath.Dir(dst))
	return nil
}

// pruneEmpty removes empty directories up towards the store root.
func (f *FS) pruneEmpty(dir string) {
	for dir != f.Dir && strings.HasPrefix(dir, f.Dir) {
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) > 0 {
			return
		}
		if os.Remove(dir) != nil {
			return
		}
		dir = filepath.Dir(dir)
	}
}

// List returns all secret names (without extension), sorted.
func (f *FS) List() ([]string, error) {
	var names []string
	err := filepath.WalkDir(f.Dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") && path != f.Dir {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), Ext) {
			return nil
		}
		rel, err := filepath.Rel(f.Dir, path)
		if err != nil {
			return err
		}
		rel = strings.TrimSuffix(filepath.ToSlash(rel), Ext)
		names = append(names, rel)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("storage: list: %w", err)
	}
	sort.Strings(names)
	return names, nil
}

// Recipients resolves the effective recipients for name by walking upward
// from the secret's directory to the store root; the nearest file wins.
func (f *FS) Recipients(name string) ([]string, error) {
	dir := filepath.Dir(f.path(name))
	for {
		rf := filepath.Join(dir, recipientsFile)
		if lines, err := readLines(rf); err == nil {
			return lines, nil
		}
		if dir == f.Dir || !strings.HasPrefix(dir, f.Dir) {
			break
		}
		dir = filepath.Dir(dir)
	}
	// Fall back to the root recipients file explicitly.
	return readLines(filepath.Join(f.Dir, recipientsFile))
}

// SetRootRecipients writes the store-root recipients file.
func (f *FS) SetRootRecipients(recipients []string) error {
	if err := os.MkdirAll(f.Dir, 0o700); err != nil {
		return fmt.Errorf("storage: mkdir root: %w", err)
	}
	data := strings.Join(recipients, "\n") + "\n"
	return atomicWrite(filepath.Join(f.Dir, recipientsFile), []byte(data), 0o600)
}

// readLines reads non-empty, non-comment lines from a file.
func readLines(path string) ([]string, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	var lines []string
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("storage: no recipients in %s", path)
	}
	return lines, nil
}

// atomicWrite writes data to path via a temp file, fsync, and rename.
func atomicWrite(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("storage: temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("storage: write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("storage: sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("storage: close temp: %w", err)
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		return fmt.Errorf("storage: chmod temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("storage: rename: %w", err)
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
