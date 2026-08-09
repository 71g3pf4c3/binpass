// Package binary handles base64-encoded binary secrets in the password store.
//
// Binary entries follow the gopass convention: they are stored as regular
// encrypted entries whose name ends in ".b64" and whose plaintext content is
// the base64 representation of the original binary data. This keeps the store
// format compatible with gopass and allows binary data to be versioned,
// synced, and re-encrypted alongside text secrets without special handling in
// the storage or crypto layers.
package binary

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/71g3pf4c3/binpass/pkg/secret"
	"github.com/71g3pf4c3/binpass/pkg/store"
)

// b64Suffix marks a binary entry.
const b64Suffix = ".b64"

// ErrNotBinary reports that an entry is not a binary secret.
var ErrNotBinary = errors.New("binary: entry is not a binary secret")

// IsBinary reports whether name refers to a binary entry (".b64" suffix).
func IsBinary(name string) bool {
	return strings.HasSuffix(name, b64Suffix)
}

// Cat decodes the binary content of the named entry and writes it to w.
// The entry must have the ".b64" suffix. The base64-decoded output streams
// to w without buffering the full decoded content in memory.
func Cat(s *store.Store, name string, w io.Writer) error {
	if !IsBinary(name) {
		return fmt.Errorf("%w: %q", ErrNotBinary, name)
	}
	sec, err := s.Get(name)
	if err != nil {
		return err
	}
	dec := base64.NewDecoder(base64.StdEncoding, strings.NewReader(sec.String()))
	_, err = io.Copy(w, dec)
	return err
}

// Sum returns the SHA-256 hash of the decoded binary content of the named
// entry, as a lowercase hex string. The entry must have the ".b64" suffix.
// The hash is computed on the stream, so the decoded content is never fully
// buffered.
func Sum(s *store.Store, name string) (string, error) {
	if !IsBinary(name) {
		return "", fmt.Errorf("%w: %q", ErrNotBinary, name)
	}
	sec, err := s.Get(name)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	dec := base64.NewDecoder(base64.StdEncoding, strings.NewReader(sec.String()))
	if _, err := io.Copy(h, dec); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// Store reads binary data from r, base64-encodes it, and stores it under
// name. The entry name must have the ".b64" suffix. The reader is consumed
// fully, including EOF.
func Store(s *store.Store, name string, r io.Reader) error {
	if !IsBinary(name) {
		return fmt.Errorf("%w: %q", ErrNotBinary, name)
	}
	encoded, err := encodeB64(r)
	if err != nil {
		return err
	}
	sec := secret.New(encoded, "")
	return s.Set(name, sec)
}

// StoreAndHash is Store that also returns the SHA-256 hash of the original
// (pre-encoding) content. Useful for verification after import.
func StoreAndHash(s *store.Store, name string, r io.Reader) (string, error) {
	if !IsBinary(name) {
		return "", fmt.Errorf("%w: %q", ErrNotBinary, name)
	}
	h := sha256.New()
	encoded, err := encodeB64(io.TeeReader(r, h))
	if err != nil {
		return "", err
	}
	sec := secret.New(encoded, "")
	if err := s.Set(name, sec); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// encodeB64 reads all of r and returns the base64-encoded string.
// For large inputs this is memory-intensive, but the crypto layer
// (store.Set) requires the full plaintext in memory anyway.
func encodeB64(r io.Reader) (string, error) {
	var buf strings.Builder
	enc := base64.NewEncoder(base64.StdEncoding, &buf)
	if _, err := io.Copy(enc, r); err != nil {
		_ = enc.Close()
		return "", err
	}
	if err := enc.Close(); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// DetectBinary reports whether a secret's content looks like a base64-encoded
// binary blob (i.e. a single line of base64 with no key: value lines).
// This is a heuristic used for display purposes, not a security check.
func DetectBinary(sec *secret.Secret) bool {
	lines := sec.Lines()
	if len(lines) != 1 {
		return false
	}
	line := lines[0]
	if len(line) < 16 {
		return false
	}
	_, err := base64.StdEncoding.DecodeString(line)
	return err == nil
}

// HashReader returns the SHA-256 hash of all data read from r, as a lowercase
// hex string. It consumes the reader fully.
func HashReader(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
