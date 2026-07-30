package crypto

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/armor"
)

// Age is the age-based Crypto implementation.
type Age struct {
	// identities are used for decryption.
	identities []age.Identity
}

// NewAge builds an Age with the given identities (may be empty for
// encrypt-only use).
func NewAge(identities []age.Identity) *Age {
	return &Age{identities: identities}
}

// ParseRecipient parses a single age or ssh recipient string.
func ParseRecipient(s string) (age.Recipient, error) {
	s = strings.TrimSpace(s)
	switch {
	case strings.HasPrefix(s, "age1"):
		return age.ParseX25519Recipient(s)
	case strings.HasPrefix(s, "ssh-"):
		return agessh.ParseRecipient(s)
	default:
		return nil, fmt.Errorf("crypto: unrecognised recipient %q", s)
	}
}

// ParseRecipients parses a list of recipient strings, skipping blanks and
// comment lines beginning with '#'.
func ParseRecipients(lines []string) ([]age.Recipient, error) {
	var out []age.Recipient
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		r, err := ParseRecipient(line)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("crypto: no recipients")
	}
	return out, nil
}

// Encrypt encrypts plaintext to recipients and writes ASCII-armored
// ciphertext to w.
func (a *Age) Encrypt(w io.Writer, plaintext []byte, recipients []string) error {
	recs, err := ParseRecipients(recipients)
	if err != nil {
		return err
	}
	armorWriter := armor.NewWriter(w)
	encWriter, err := age.Encrypt(armorWriter, recs...)
	if err != nil {
		return fmt.Errorf("crypto: encrypt init: %w", err)
	}
	if _, err := encWriter.Write(plaintext); err != nil {
		return fmt.Errorf("crypto: encrypt write: %w", err)
	}
	if err := encWriter.Close(); err != nil {
		return fmt.Errorf("crypto: encrypt close: %w", err)
	}
	return armorWriter.Close()
}

// Decrypt decrypts ciphertext, transparently handling ASCII-armored input.
func (a *Age) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(a.identities) == 0 {
		return nil, fmt.Errorf("crypto: no identities loaded")
	}
	var r io.Reader = bytes.NewReader(ciphertext)
	if bytes.Contains(ciphertext, []byte(armor.Header)) {
		r = armor.NewReader(r)
	}
	dec, err := age.Decrypt(r, a.identities...)
	if err != nil {
		return nil, fmt.Errorf("crypto: decrypt: %w", err)
	}
	out, err := io.ReadAll(dec)
	if err != nil {
		return nil, fmt.Errorf("crypto: read plaintext: %w", err)
	}
	return out, nil
}
