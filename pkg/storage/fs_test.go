package storage

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteReadRemove(t *testing.T) {
	fs := New(t.TempDir())
	require.NoError(t, fs.Write("github.com/alice", []byte("ct")))
	assert.True(t, fs.Exists("github.com/alice"))

	data, err := fs.Read("github.com/alice")
	require.NoError(t, err)
	assert.Equal(t, []byte("ct"), data)

	// File must be 0600.
	info, err := os.Stat(filepath.Join(fs.Dir, "github.com", "alice.age"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	require.NoError(t, fs.Remove("github.com/alice"))
	assert.False(t, fs.Exists("github.com/alice"))
	// Empty parent dir should be pruned.
	_, err = os.Stat(filepath.Join(fs.Dir, "github.com"))
	assert.True(t, os.IsNotExist(err))
}

func TestList(t *testing.T) {
	fs := New(t.TempDir())
	require.NoError(t, fs.Write("b", []byte("x")))
	require.NoError(t, fs.Write("a/c", []byte("x")))
	names, err := fs.List()
	require.NoError(t, err)
	assert.Equal(t, []string{"a/c", "b"}, names)
}

func TestRecipientsHierarchy(t *testing.T) {
	fs := New(t.TempDir())
	require.NoError(t, fs.SetRootRecipients([]string{"age1root"}))
	require.NoError(t, os.MkdirAll(filepath.Join(fs.Dir, "bank"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(fs.Dir, "bank", recipientsFile), []byte("age1bank\n"), 0o600))

	root, err := fs.Recipients("top")
	require.NoError(t, err)
	assert.Equal(t, []string{"age1root"}, root)

	bank, err := fs.Recipients("bank/card")
	require.NoError(t, err)
	assert.Equal(t, []string{"age1bank"}, bank)
}
