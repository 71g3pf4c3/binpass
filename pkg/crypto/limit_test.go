package crypto_test

import (
	"bytes"
	"io"
	"testing"

	"filippo.io/age"
	"github.com/71g3pf4c3/binpass/pkg/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// zeroes is an endless reader used to build oversize input without holding
// it anywhere.
type zeroes struct{}

// Read implements io.Reader.
func (zeroes) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// TestDecryptRejectsOversizeInput covers the memory-exhaustion case from a
// hostile remote: ciphertext is encrypted to the victim's public recipients,
// so anyone who can write to the store can choose how much the next `show`
// tries to hold in memory. Refusing must be a hard error — a truncated
// plaintext would be used as if it were the secret.
func TestDecryptRejectsOversizeInput(t *testing.T) {
	tests := []struct {
		name    string
		size    int64
		wantErr bool
	}{
		{name: "at the bound", size: crypto.MaxEntryBytes},
		{name: "one byte over", size: crypto.MaxEntryBytes + 1, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The bound is checked before gpg is resolved, so this holds
			// on a machine without gpg too.
			g := crypto.NewGPG(t.TempDir(), "", nil)
			_, err := g.Decrypt(io.LimitReader(zeroes{}, tt.size))
			if tt.wantErr {
				assert.ErrorIs(t, err, crypto.ErrTooLarge)
				return
			}
			assert.NotErrorIs(t, err, crypto.ErrTooLarge, "an entry-sized ciphertext must reach gpg")
		})
	}
}

// TestAgeDecryptRejectsOversizePlaintext bounds what age expands to: the
// ciphertext may be small while the plaintext is not.
func TestAgeDecryptRejectsOversizePlaintext(t *testing.T) {
	id, rcp := newIdentity(t)
	a := crypto.NewAge(t.TempDir(), func() ([]age.Identity, error) {
		return []age.Identity{id}, nil
	})

	var ct bytes.Buffer
	recipients, err := crypto.ParseAgeRecipients([]crypto.Recipient{rcp})
	require.NoError(t, err)
	w, err := age.Encrypt(&ct, recipients...)
	require.NoError(t, err)
	_, err = io.Copy(w, io.LimitReader(zeroes{}, crypto.MaxEntryBytes+1))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	_, err = a.Decrypt(bytes.NewReader(ct.Bytes()))
	assert.ErrorIs(t, err, crypto.ErrTooLarge)
}
