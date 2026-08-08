package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShredRemovesTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.txt")
	require.NoError(t, os.WriteFile(path, []byte("hunter2"), 0o600))

	require.NoError(t, shred(path))
	_, err := os.Stat(path)
	assert.True(t, os.IsNotExist(err), "the plaintext file must be gone")
}

func TestShredHandlesAnEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.txt")
	require.NoError(t, os.WriteFile(path, nil, 0o600))

	require.NoError(t, shred(path))
	_, err := os.Stat(path)
	assert.True(t, os.IsNotExist(err))
}

func TestShredOnAMissingFile(t *testing.T) {
	assert.Error(t, shred(filepath.Join(t.TempDir(), "never-existed")))
}

func TestSecureTempDirIsUsable(t *testing.T) {
	dir := secureTempDir()
	// An empty string means "the system default", which is always usable.
	f, err := os.CreateTemp(dir, "probe-*")
	require.NoError(t, err)
	name := f.Name()
	require.NoError(t, f.Close())
	require.NoError(t, os.Remove(name))
}
