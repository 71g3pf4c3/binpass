// Package crypto encrypts and decrypts individual store entries.
//
// Two implementations coexist in one tree and are selected by file extension:
// GPG (.gpg, via the external gpg binary, for byte-identical pass
// compatibility and smartcard support) and age (.age, via filippo.io/age).
package crypto

import (
	"errors"
	"io"
)

// ErrNoRecipients reports that an encrypt was requested without any recipient.
var ErrNoRecipients = errors.New("crypto: no recipients")

// ErrNoIdentity reports that no identity could decrypt the ciphertext.
var ErrNoIdentity = errors.New("crypto: no usable identity")

// Recipient is a public key a secret can be encrypted to. Its meaning is
// backend-specific: a GPG key ID or fingerprint, or an age recipient string.
type Recipient string

// String returns the recipient in its on-disk textual form.
func (r Recipient) String() string { return string(r) }

// Crypto encrypts and decrypts a single entry.
type Crypto interface {
	// Ext is the file extension entries of this backend carry, including the
	// leading dot: ".gpg" or ".age".
	Ext() string

	// Encrypt writes the ciphertext of plaintext, readable by rcp, to w.
	Encrypt(w io.Writer, plaintext []byte, rcp []Recipient) error

	// Decrypt reads a ciphertext from r and returns its plaintext.
	Decrypt(r io.Reader) ([]byte, error)

	// RecipientsFile is the name of the file listing recipients for a
	// directory: ".gpg-id" or ".age-recipients".
	RecipientsFile() string

	// ParseRecipients reads the recipients governing dir, walking up to the
	// store root as pass does: the nearest recipients file wins.
	ParseRecipients(dir string) ([]Recipient, error)

	// Available reports whether the backend can run in this environment; the
	// GPG backend needs the gpg binary on PATH.
	Available() error
}
