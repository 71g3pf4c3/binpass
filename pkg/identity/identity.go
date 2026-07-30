// Package identity loads and unlocks age identities used for decryption and
// derives the recipient of a freshly generated identity.
package identity

import (
	"fmt"
	"os"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
)

// GenerateX25519 creates a new X25519 identity.
func GenerateX25519() (*age.X25519Identity, error) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("identity: generate: %w", err)
	}
	return id, nil
}

// LoadFile parses identities from an age key file. Lines beginning with
// AGE-SECRET-KEY or SSH private key blocks are recognised.
func LoadFile(path string) ([]age.Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("identity: read %s: %w", path, err)
	}
	return Parse(data, path)
}

// Parse decodes identities from raw key-file bytes. sshPath is used only for
// error messages and passphrase prompts on SSH keys.
func Parse(data []byte, sshPath string) ([]age.Identity, error) {
	if looksLikeSSHKey(data) {
		id, err := agessh.ParseIdentity(data)
		if err != nil {
			return nil, fmt.Errorf("identity: parse ssh key %s: %w", sshPath, err)
		}
		return []age.Identity{id}, nil
	}
	ids, err := age.ParseIdentities(strings.NewReader(string(data)))
	if err != nil {
		return nil, fmt.Errorf("identity: parse: %w", err)
	}
	return ids, nil
}

// FirstX25519Recipient returns the recipient string of the first X25519
// identity in ids, if any.
func FirstX25519Recipient(ids []age.Identity) (string, bool) {
	for _, id := range ids {
		if x, ok := id.(*age.X25519Identity); ok {
			return x.Recipient().String(), true
		}
	}
	return "", false
}

// looksLikeSSHKey reports whether data is an OpenSSH private key.
func looksLikeSSHKey(data []byte) bool {
	return strings.Contains(string(data), "OPENSSH PRIVATE KEY") ||
		strings.Contains(string(data), "BEGIN RSA PRIVATE KEY")
}
