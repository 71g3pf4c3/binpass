package crypto_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/71g3pf4c3/binpass/pkg/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newIdentity returns a fresh age keypair for a test.
func newIdentity(t *testing.T) (*age.X25519Identity, crypto.Recipient) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	return id, crypto.Recipient(id.Recipient().String())
}

func TestAgeRoundTrip(t *testing.T) {
	id, rcp := newIdentity(t)
	a := crypto.NewAge(t.TempDir(), func() ([]age.Identity, error) {
		return []age.Identity{id}, nil
	})

	plaintext := []byte("hunter2\nurl: https://example.com\n")
	var buf bytes.Buffer
	require.NoError(t, a.Encrypt(&buf, plaintext, []crypto.Recipient{rcp}))
	assert.NotContains(t, buf.String(), "hunter2")

	got, err := a.Decrypt(&buf)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)
}

func TestAgeDecryptWithWrongIdentity(t *testing.T) {
	_, rcp := newIdentity(t)
	other, _ := newIdentity(t)

	enc := crypto.NewAge(t.TempDir(), nil)
	var buf bytes.Buffer
	require.NoError(t, enc.Encrypt(&buf, []byte("secret"), []crypto.Recipient{rcp}))

	dec := crypto.NewAge(t.TempDir(), func() ([]age.Identity, error) {
		return []age.Identity{other}, nil
	})
	_, err := dec.Decrypt(&buf)
	assert.Error(t, err)
}

func TestAgeEncryptWithoutRecipients(t *testing.T) {
	a := crypto.NewAge(t.TempDir(), nil)
	err := a.Encrypt(&bytes.Buffer{}, []byte("x"), nil)
	assert.ErrorIs(t, err, crypto.ErrNoRecipients)
}

func TestAgeDecryptWithoutIdentity(t *testing.T) {
	a := crypto.NewAge(t.TempDir(), nil)
	_, err := a.Decrypt(bytes.NewReader(nil))
	assert.ErrorIs(t, err, crypto.ErrNoIdentity)
}

func TestAgeIdentitiesAreLazy(t *testing.T) {
	_, rcp := newIdentity(t)
	called := false
	a := crypto.NewAge(t.TempDir(), func() ([]age.Identity, error) {
		called = true
		return nil, nil
	})
	require.NoError(t, a.Encrypt(&bytes.Buffer{}, []byte("x"), []crypto.Recipient{rcp}))
	assert.False(t, called, "encrypting must not touch identities")
}

func TestAgeExtAndRecipientsFile(t *testing.T) {
	a := crypto.NewAge(t.TempDir(), nil)
	assert.Equal(t, ".age", a.Ext())
	assert.Equal(t, ".age-recipients", a.RecipientsFile())
	assert.NoError(t, a.Available())
}

func TestParseAgeRecipient(t *testing.T) {
	_, rcp := newIdentity(t)

	_, err := crypto.ParseAgeRecipient(rcp.String())
	assert.NoError(t, err)

	_, err = crypto.ParseAgeRecipient("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ7hIQx0LP0hLmFcAqYlEbLuBrHiLqoAAxRxaGF0ZXZlcg== user@host")
	assert.Error(t, err, "a malformed ssh key is rejected")

	_, err = crypto.ParseAgeRecipient("not-a-recipient")
	assert.Error(t, err)
}

func TestAgeParseRecipientsNearestWins(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "bank", "ru")
	require.NoError(t, os.MkdirAll(sub, 0o700))

	_, rootRcp := newIdentity(t)
	_, bankRcp := newIdentity(t)
	writeRecipients(t, filepath.Join(root, ".age-recipients"), rootRcp)
	writeRecipients(t, filepath.Join(root, "bank", ".age-recipients"), bankRcp)

	a := crypto.NewAge(root, nil)

	got, err := a.ParseRecipients(root)
	require.NoError(t, err)
	assert.Equal(t, []crypto.Recipient{rootRcp}, got)

	got, err = a.ParseRecipients(sub)
	require.NoError(t, err)
	assert.Equal(t, []crypto.Recipient{bankRcp}, got, "the nearest recipients file governs a subtree")
}

func TestParseRecipientsSkipsCommentsAndBlanks(t *testing.T) {
	root := t.TempDir()
	_, rcp := newIdentity(t)
	body := "# team keys\n\n" + rcp.String() + "\n\n"
	require.NoError(t, os.WriteFile(filepath.Join(root, ".age-recipients"), []byte(body), 0o600))

	got, err := crypto.NewAge(root, nil).ParseRecipients(root)
	require.NoError(t, err)
	assert.Equal(t, []crypto.Recipient{rcp}, got)
}

func TestParseRecipientsErrors(t *testing.T) {
	root := t.TempDir()
	a := crypto.NewAge(root, nil)

	_, err := a.ParseRecipients(root)
	assert.Error(t, err, "a store with no recipients file")

	require.NoError(t, os.WriteFile(filepath.Join(root, ".age-recipients"), []byte("# only a comment\n"), 0o600))
	_, err = a.ParseRecipients(root)
	assert.Error(t, err, "a recipients file listing nobody")

	_, err = a.ParseRecipients(filepath.Dir(root))
	assert.Error(t, err, "a directory outside the store")
}

func TestWriteRecipients(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", ".age-recipients")
	_, rcp := newIdentity(t)
	require.NoError(t, crypto.WriteRecipients(path, []crypto.Recipient{rcp}))

	st, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), st.Mode().Perm())

	assert.ErrorIs(t, crypto.WriteRecipients(path, nil), crypto.ErrNoRecipients)
}

// writeRecipients writes a recipients file for a test fixture.
func writeRecipients(t *testing.T, path string, rcp crypto.Recipient) {
	t.Helper()
	require.NoError(t, crypto.WriteRecipients(path, []crypto.Recipient{rcp}))
}
