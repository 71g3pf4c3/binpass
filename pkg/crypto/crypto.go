// Package crypto provides the encryption abstraction used by binpass.
//
// The primary implementation is age (filippo.io/age). Crypto encrypts a
// plaintext to a set of recipients and decrypts using one or more
// identities. GPG is intentionally not implemented here; it exists only as a
// read-only migration bridge elsewhere.
package crypto

import "io"

// Crypto encrypts and decrypts secret payloads.
type Crypto interface {
	// Encrypt writes ciphertext for plaintext to w, for the given recipients.
	Encrypt(w io.Writer, plaintext []byte, recipients []string) error
	// Decrypt returns the plaintext of ciphertext using the loaded identities.
	Decrypt(ciphertext []byte) ([]byte, error)
}
