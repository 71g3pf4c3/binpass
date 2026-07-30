package identity

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateAndParse(t *testing.T) {
	id, err := GenerateX25519()
	require.NoError(t, err)

	dir := t.TempDir()
	path := filepath.Join(dir, "identities.age")
	require.NoError(t, os.WriteFile(path, []byte(id.String()+"\n"), 0o600))

	ids, err := LoadFile(path)
	require.NoError(t, err)
	require.Len(t, ids, 1)

	rec, ok := FirstX25519Recipient(ids)
	require.True(t, ok)
	assert.Equal(t, id.Recipient().String(), rec)
}

func TestLoadMissing(t *testing.T) {
	_, err := LoadFile(filepath.Join(t.TempDir(), "nope"))
	assert.Error(t, err)
}

func TestParseInvalid(t *testing.T) {
	_, err := Parse([]byte("not a key"), "x")
	assert.Error(t, err)
}
