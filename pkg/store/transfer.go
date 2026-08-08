package store

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/71g3pf4c3/binpass/pkg/crypto"
)

// transfer implements Move and Copy. Both share the same subtlety: a name may
// denote an entry or a subfolder, a destination may be a subfolder to move
// into, and the destination's recipients may differ from the source's.
func (s *Store) transfer(from, to string, remove bool) error {
	if s.IsDir(from) {
		return s.transferDir(from, to, remove)
	}
	if !s.Exists(from) {
		return fmt.Errorf("%w: %s", ErrNotFound, from)
	}
	return s.transferEntry(from, s.resolveDest(from, to), remove)
}

// resolveDest expands a destination that names a subfolder, or ends in a
// slash, into a full entry name, mirroring mv(1) and pass.
func (s *Store) resolveDest(from, to string) string {
	if strings.HasSuffix(to, "/") || s.IsDir(to) {
		return strings.TrimSuffix(to, "/") + "/" + filepath.Base(from)
	}
	return to
}

// transferEntry moves or copies a single entry, re-encrypting it when the
// destination is governed by different recipients.
func (s *Store) transferEntry(from, to string, remove bool) error {
	sec, err := s.Get(from)
	if err != nil {
		return err
	}
	srcPath, err := s.fs.Find(from, s.exts())
	if err != nil {
		return err
	}
	backend, err := s.backendFor(filepath.Ext(srcPath))
	if err != nil {
		return err
	}
	dstPath, err := s.fs.Path(to, backend.Ext())
	if err != nil {
		return err
	}

	same, err := s.sameRecipients(backend, filepath.Dir(srcPath), filepath.Dir(dstPath))
	if err != nil {
		return err
	}
	if same {
		// Recipients are unchanged: move the ciphertext as it is, so a plain
		// rename never needs a key and never touches a hardware token.
		if remove {
			return s.fs.Rename(srcPath, dstPath)
		}
		data, err := s.fs.Read(srcPath)
		if err != nil {
			return err
		}
		return s.fs.Write(dstPath, data)
	}

	if err := s.writeWith(to, sec, backend); err != nil {
		return err
	}
	if remove {
		return s.fs.Remove(srcPath)
	}
	return nil
}

// transferDir moves or copies a whole subtree entry by entry, so that every
// entry lands re-encrypted for wherever it ends up.
func (s *Store) transferDir(from, to string, remove bool) error {
	entries, err := s.fs.Entries(from, s.exts())
	if err != nil {
		return err
	}
	dest := to
	if s.IsDir(to) || strings.HasSuffix(to, "/") {
		dest = strings.TrimSuffix(to, "/") + "/" + filepath.Base(from)
	}
	for _, e := range entries {
		rel := strings.TrimPrefix(e.Name, strings.TrimSuffix(from, "/")+"/")
		if err := s.transferEntry(e.Name, dest+"/"+rel, remove); err != nil {
			return err
		}
	}
	if remove {
		return s.RemoveDir(from)
	}
	return nil
}

// sameRecipients reports whether two directories are governed by an identical
// recipient set, order-insensitively.
func (s *Store) sameRecipients(backend crypto.Crypto, a, b string) (bool, error) {
	if a == b {
		return true, nil
	}
	ra, err := backend.ParseRecipients(a)
	if err != nil {
		return false, err
	}
	rb, err := backend.ParseRecipients(b)
	if err != nil {
		return false, err
	}
	if len(ra) != len(rb) {
		return false, nil
	}
	seen := make(map[crypto.Recipient]int, len(ra))
	for _, r := range ra {
		seen[r]++
	}
	for _, r := range rb {
		seen[r]--
		if seen[r] < 0 {
			return false, nil
		}
	}
	return true, nil
}
