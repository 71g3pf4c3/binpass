// Package store is the facade over a password store: it binds the on-disk
// tree to the crypto backends and the secret format.
//
// A store may hold GPG and age entries side by side. The backend for an
// existing entry follows its file extension; the backend for a new entry
// follows the store's configured default.
package store

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/71g3pf4c3/binpass/pkg/crypto"
	"github.com/71g3pf4c3/binpass/pkg/secret"
	"github.com/71g3pf4c3/binpass/pkg/storage"
)

// ErrNotFound reports that an entry does not exist.
var ErrNotFound = errors.New("store: entry not found")

// ErrExists reports a refusal to overwrite an existing entry.
var ErrExists = errors.New("store: entry already exists")

// ErrNotInitialised reports a store with no recipients file at its root.
var ErrNotInitialised = errors.New("store: not initialised")

// Store is a password store bound to a directory and its crypto backends.
type Store struct {
	// fs is the on-disk layout.
	fs *storage.FS
	// backends are the available crypto implementations, in the order
	// existing entries are looked up.
	backends []crypto.Crypto
	// def is the backend new entries are created with.
	def crypto.Crypto
}

// Options configures a Store.
type Options struct {
	// Dir is the store root.
	Dir string
	// Backends are the crypto implementations to support, in lookup order.
	Backends []crypto.Crypto
	// Default is the backend for new entries; it must be one of Backends.
	Default crypto.Crypto
	// Umask masks created file permissions; zero means pass's 077.
	Umask os.FileMode
}

// New returns a Store from opts.
func New(opts Options) (*Store, error) {
	if len(opts.Backends) == 0 {
		return nil, errors.New("store: no crypto backends configured")
	}
	def := opts.Default
	if def == nil {
		def = opts.Backends[0]
	}
	f := storage.New(opts.Dir)
	if opts.Umask != 0 {
		f.Umask = opts.Umask
	}
	return &Store{fs: f, backends: opts.Backends, def: def}, nil
}

// Dir returns the store root.
func (s *Store) Dir() string { return s.fs.Dir }

// exts returns the crypto extensions in lookup order.
func (s *Store) exts() []string {
	out := make([]string, 0, len(s.backends))
	for _, b := range s.backends {
		out = append(out, b.Ext())
	}
	return out
}

// backendFor returns the backend handling the given extension.
func (s *Store) backendFor(ext string) (crypto.Crypto, error) {
	for _, b := range s.backends {
		if b.Ext() == ext {
			return b, nil
		}
	}
	return nil, fmt.Errorf("store: no backend for %q entries", ext)
}

// Initialised reports whether the store root carries a recipients file for any
// configured backend.
func (s *Store) Initialised() bool {
	for _, b := range s.backends {
		if _, err := os.Stat(filepath.Join(s.fs.Dir, b.RecipientsFile())); err == nil {
			return true
		}
	}
	return false
}

// Init writes the recipients file for sub (empty for the store root) using the
// default backend, creating the store directory if needed.
func (s *Store) Init(sub string, rcp []crypto.Recipient) error {
	dir, err := s.fs.DirPath(sub)
	if err != nil {
		return err
	}
	if err := s.fs.MkdirAll(dir); err != nil {
		return err
	}
	return crypto.WriteRecipients(filepath.Join(dir, s.def.RecipientsFile()), rcp)
}

// Exists reports whether an entry called name exists.
func (s *Store) Exists(name string) bool {
	_, err := s.fs.Find(name, s.exts())
	return err == nil
}

// IsDir reports whether name is a subfolder of the store.
func (s *Store) IsDir(name string) bool { return s.fs.IsDir(name) }

// Get decrypts the entry called name.
func (s *Store) Get(name string) (*secret.Secret, error) {
	path, err := s.fs.Find(name, s.exts())
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, name)
		}
		return nil, err
	}
	backend, err := s.backendFor(filepath.Ext(path))
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path) //nolint:gosec // the path came from the store tree.
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	plaintext, err := backend.Decrypt(f)
	if err != nil {
		return nil, fmt.Errorf("store: %s: %w", name, err)
	}
	return secret.Parse(plaintext), nil
}

// Set encrypts sec and stores it as name, replacing any existing entry. An
// existing entry keeps its crypto backend, so writing to a .gpg entry never
// silently converts it to age.
func (s *Store) Set(name string, sec *secret.Secret) error {
	path, backend, err := s.target(name)
	if err != nil {
		return err
	}
	rcp, err := backend.ParseRecipients(filepath.Dir(path))
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := backend.Encrypt(&buf, sec.Bytes(), rcp); err != nil {
		return err
	}
	return s.fs.Write(path, buf.Bytes())
}

// target resolves where an entry should be written and with which backend.
func (s *Store) target(name string) (path string, backend crypto.Crypto, err error) {
	if existing, err := s.fs.Find(name, s.exts()); err == nil {
		b, err := s.backendFor(filepath.Ext(existing))
		if err != nil {
			return "", nil, err
		}
		return existing, b, nil
	}
	b, err := s.backendForNew(name)
	if err != nil {
		return "", nil, err
	}
	path, err = s.fs.Path(name, b.Ext())
	if err != nil {
		return "", nil, err
	}
	return path, b, nil
}

// backendForNew picks the backend for an entry that does not exist yet.
//
// The configured default applies only when the destination actually has
// recipients for it. A GPG-only store must keep receiving .gpg entries even
// when age is the global default, or binpass would silently write files the
// user's pass installation cannot read.
func (s *Store) backendForNew(name string) (crypto.Crypto, error) {
	dir, err := s.fs.DirPath(name)
	if err != nil {
		return nil, err
	}
	dir = filepath.Dir(dir)

	if _, err := s.def.ParseRecipients(dir); err == nil {
		return s.def, nil
	}
	for _, b := range s.backends {
		if b == s.def {
			continue
		}
		if _, err := b.ParseRecipients(dir); err == nil {
			return b, nil
		}
	}
	// Nothing is configured anywhere: report the default's own error, which
	// names the file the user is expected to create.
	_, err = s.def.ParseRecipients(dir)
	return nil, err
}

// SetNew is Set that refuses to overwrite an existing entry.
func (s *Store) SetNew(name string, sec *secret.Secret) error {
	if s.Exists(name) {
		return fmt.Errorf("%w: %s", ErrExists, name)
	}
	return s.Set(name, sec)
}

// List returns the entry names under sub, sorted.
func (s *Store) List(sub string) ([]string, error) {
	entries, err := s.fs.Entries(sub, s.exts())
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name)
	}
	return out, nil
}

// Remove deletes the entry called name.
func (s *Store) Remove(name string) error {
	path, err := s.fs.Find(name, s.exts())
	if err != nil {
		return fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	return s.fs.Remove(path)
}

// RemoveDir deletes the subfolder called name and everything under it.
func (s *Store) RemoveDir(name string) error {
	dir, err := s.fs.DirPath(name)
	if err != nil {
		return err
	}
	if dir == s.fs.Dir {
		return errors.New("store: refusing to remove the store root")
	}
	return os.RemoveAll(dir)
}

// Move renames an entry or a subfolder. Entries whose recipients change as a
// result are re-encrypted, since a move into a differently shared subtree
// would otherwise leave a secret readable by the wrong people.
func (s *Store) Move(from, to string) error {
	return s.transfer(from, to, true)
}

// Copy duplicates an entry or a subfolder, re-encrypting as Move does.
func (s *Store) Copy(from, to string) error {
	return s.transfer(from, to, false)
}

// Reencrypt rewrites every entry under sub for its current recipients. It is
// how a recipient change takes effect, and how migration between backends is
// carried out when to is non-nil.
func (s *Store) Reencrypt(sub string, to crypto.Crypto) error {
	entries, err := s.fs.Entries(sub, s.exts())
	if err != nil {
		return err
	}
	for _, e := range entries {
		sec, err := s.Get(e.Name)
		if err != nil {
			return err
		}
		target := to
		if target == nil {
			target, err = s.backendFor(e.Ext)
			if err != nil {
				return err
			}
		}
		if err := s.writeWith(e.Name, sec, target); err != nil {
			return err
		}
		// Migrating between backends changes the extension, so the old file
		// must go, or the entry would exist twice with diverging contents.
		if target.Ext() != e.Ext {
			if err := s.fs.Remove(e.Path); err != nil {
				return err
			}
		}
	}
	return nil
}

// writeWith encrypts sec as name using an explicit backend.
func (s *Store) writeWith(name string, sec *secret.Secret, backend crypto.Crypto) error {
	path, err := s.fs.Path(name, backend.Ext())
	if err != nil {
		return err
	}
	rcp, err := backend.ParseRecipients(filepath.Dir(path))
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := backend.Encrypt(&buf, sec.Bytes(), rcp); err != nil {
		return err
	}
	return s.fs.Write(path, buf.Bytes())
}

// Recipients returns the recipients governing name for its backend.
func (s *Store) Recipients(name string) ([]crypto.Recipient, error) {
	dir, err := s.fs.DirPath(name)
	if err != nil {
		return nil, err
	}
	if !s.fs.IsDir(name) {
		dir = filepath.Dir(dir)
	}
	return s.def.ParseRecipients(dir)
}

// Grep decrypts every entry under sub and reports those whose plaintext
// satisfies match.
func (s *Store) Grep(sub string, match func(string) bool) ([]Match, error) {
	entries, err := s.fs.Entries(sub, s.exts())
	if err != nil {
		return nil, err
	}
	var out []Match
	for _, e := range entries {
		sec, err := s.Get(e.Name)
		if err != nil {
			return nil, err
		}
		var lines []string
		for _, line := range sec.Lines() {
			if match(line) {
				lines = append(lines, line)
			}
		}
		if len(lines) > 0 {
			out = append(out, Match{Name: e.Name, Lines: lines})
		}
	}
	return out, nil
}

// Match is one entry containing lines that satisfied a Grep.
type Match struct {
	// Name is the entry name.
	Name string
	// Lines are the matching plaintext lines.
	Lines []string
}

// Find returns the names of entries whose path contains any of the terms,
// case-insensitively.
func (s *Store) Find(terms []string) ([]string, error) {
	names, err := s.List("")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, name := range names {
		lower := strings.ToLower(name)
		for _, term := range terms {
			if strings.Contains(lower, strings.ToLower(term)) {
				out = append(out, name)
				break
			}
		}
	}
	return out, nil
}
