package crypto

import (
	"bytes"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	enc := NewAge(nil)
	var buf bytes.Buffer
	plaintext := []byte("hunter2\nusername: alice\n")
	require.NoError(t, enc.Encrypt(&buf, plaintext, []string{id.Recipient().String()}))

	dec := NewAge([]age.Identity{id})
	got, err := dec.Decrypt(buf.Bytes())
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)
}

func TestDecryptWithoutIdentity(t *testing.T) {
	_, err := NewAge(nil).Decrypt([]byte("garbage"))
	assert.Error(t, err)
}

func TestParseRecipients(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	lines := []string{"# comment", "", id.Recipient().String()}
	recs, err := ParseRecipients(lines)
	require.NoError(t, err)
	assert.Len(t, recs, 1)

	_, err = ParseRecipients([]string{"# only comment"})
	assert.Error(t, err)
}

func TestParseRecipientBad(t *testing.T) {
	_, err := ParseRecipient("not-a-key")
	assert.Error(t, err)
}
