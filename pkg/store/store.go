// Package store is the high-level facade over the password store: it wires
// together the filesystem layout, age crypto, and the secret format to
// provide Get/Set/List/Move/Copy/Remove/Reencrypt operations.
package store

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/71g3pf4c3/binpass/pkg/crypto"
	"github.com/71g3pf4c3/binpass/pkg/secret"
	"github.com/71g3pf4c3/binpass/pkg/storage"
)

// ErrNotFound is returned when a secret does not exist.
var ErrNotFound = errors.New("store: secret not found")

// ErrExists is returned when refusing to overwrite an existing secret.
var ErrExists = errors.New("store: secret already exists")

// Store is a password store bound to a directory and crypto backend.
type Store struct {
	// fs is the on-disk layout.
	fs *storage.FS
	// crypto encrypts and decrypts secret payloads.
	crypto crypto.Crypto
}

// New returns a Store rooted at dir using the given crypto backend.
func New(dir string, c crypto.Crypto) *Store {
	return &Store{fs: storage.New(dir), crypto: c}
}

// Dir returns the store root directory.
func (s *Store) Dir() string { return s.fs.Dir }

// Initialised reports whether the store has a root recipients file.
func (s *Store) Initialised() bool {
	_, err := os.Stat(filepath.Join(s.fs.Dir, ".age-recipients"))
	return err == nil
}

// Init creates the store directory and writes the root recipients file.
func (s *Store) Init(recipients []string) error {
	return s.fs.SetRootRecipients(recipients)
}

// InitSub writes a recipients override for the given subfolder.
func (s *Store) InitSub(sub string, recipients []string) error {
	return s.fs.SetSubRecipients(sub, recipients)
}

// Exists reports whether name exists in the store.
func (s *Store) Exists(name string) bool { return s.fs.Exists(name) }

// ReadCiphertext returns the raw (still-encrypted) bytes stored under name.
func (s *Store) ReadCiphertext(name string) ([]byte, error) { return s.fs.Read(name) }

// WriteCiphertext stores already-encrypted bytes verbatim under name.
func (s *Store) WriteCiphertext(name string, ciphertext []byte) error {
	return s.fs.Write(name, ciphertext)
}

// RemoveByName deletes name without decrypting it (used by sync).
func (s *Store) RemoveByName(name string) error { return s.fs.Remove(name) }

// RemoveDir recursively removes every secret under the given prefix. It
// returns the removed names and ErrNotFound if the prefix matches nothing.
func (s *Store) RemoveDir(prefix string) ([]string, error) {
	names, err := s.fs.List()
	if err != nil {
		return nil, err
	}
	trimmed := strings.Trim(prefix, "/")
	var removed []string
	for _, n := range names {
		if n == trimmed || strings.HasPrefix(n, trimmed+"/") {
			if err := s.fs.Remove(n); err != nil {
				return removed, err
			}
			removed = append(removed, n)
		}
	}
	if len(removed) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, prefix)
	}
	return removed, nil
}

// List returns all secret names, sorted.
func (s *Store) List() ([]string, error) { return s.fs.List() }

// GetRaw returns the decrypted plaintext bytes for name.
func (s *Store) GetRaw(name string) ([]byte, error) {
	if !s.fs.Exists(name) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	ct, err := s.fs.Read(name)
	if err != nil {
		return nil, err
	}
	return s.crypto.Decrypt(ct)
}

// Get returns the parsed secret for name.
func (s *Store) Get(name string) (*secret.Secret, error) {
	data, err := s.GetRaw(name)
	if err != nil {
		return nil, err
	}
	return secret.Parse(data)
}

// SetRaw encrypts and stores plaintext under name.
func (s *Store) SetRaw(name string, plaintext []byte) error {
	recs, err := s.fs.Recipients(name)
	if err != nil {
		return fmt.Errorf("store: recipients for %s: %w", name, err)
	}
	var buf bytes.Buffer
	if err := s.crypto.Encrypt(&buf, plaintext, recs); err != nil {
		return err
	}
	return s.fs.Write(name, buf.Bytes())
}

// Set serialises and stores a parsed secret under name.
func (s *Store) Set(name string, sec *secret.Secret) error {
	return s.SetRaw(name, sec.Bytes())
}

// Remove deletes the secret named name.
func (s *Store) Remove(name string) error {
	if !s.fs.Exists(name) {
		return fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	return s.fs.Remove(name)
}

// Move renames src to dst, re-encrypting to dst's recipients.
func (s *Store) Move(src, dst string, force bool) error {
	if err := s.copyOrMove(src, dst, force); err != nil {
		return err
	}
	return s.fs.Remove(src)
}

// Copy duplicates src to dst, re-encrypting to dst's recipients.
func (s *Store) Copy(src, dst string, force bool) error {
	return s.copyOrMove(src, dst, force)
}

// copyOrMove decrypts src and stores it at dst, honouring force.
func (s *Store) copyOrMove(src, dst string, force bool) error {
	if !s.fs.Exists(src) {
		return fmt.Errorf("%w: %s", ErrNotFound, src)
	}
	if s.fs.Exists(dst) && !force {
		return fmt.Errorf("%w: %s", ErrExists, dst)
	}
	plain, err := s.GetRaw(src)
	if err != nil {
		return err
	}
	return s.SetRaw(dst, plain)
}

// Reencrypt re-encrypts every secret to its current recipients (used after
// changing the recipients set).
func (s *Store) Reencrypt() error {
	names, err := s.fs.List()
	if err != nil {
		return err
	}
	for _, name := range names {
		plain, err := s.GetRaw(name)
		if err != nil {
			return fmt.Errorf("store: reencrypt %s: %w", name, err)
		}
		if err := s.SetRaw(name, plain); err != nil {
			return err
		}
	}
	return nil
}

// Find returns names containing the substring term (case-insensitive).
func (s *Store) Find(term string) ([]string, error) {
	names, err := s.fs.List()
	if err != nil {
		return nil, err
	}
	term = strings.ToLower(term)
	var out []string
	for _, n := range names {
		if strings.Contains(strings.ToLower(n), term) {
			out = append(out, n)
		}
	}
	return out, nil
}

// GrepMatch is a single hit from Grep.
type GrepMatch struct {
	// Name is the secret in which the match occurred.
	Name string
	// Line is the matching decrypted line.
	Line string
}

// Grep decrypts every secret and returns lines containing term.
func (s *Store) Grep(term string) ([]GrepMatch, error) {
	names, err := s.fs.List()
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	var out []GrepMatch
	for _, n := range names {
		plain, err := s.GetRaw(n)
		if err != nil {
			return nil, fmt.Errorf("store: grep %s: %w", n, err)
		}
		for _, line := range strings.Split(string(plain), "\n") {
			if strings.Contains(line, term) {
				out = append(out, GrepMatch{Name: n, Line: line})
			}
		}
	}
	return out, nil
}
