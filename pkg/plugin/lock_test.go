package plugin_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/71g3pf4c3/binpass/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// manifest builds a manifest for the grant tests.
func manifest(t *testing.T, caps plugin.Capabilities) *plugin.Manifest {
	t.Helper()
	m := &plugin.Manifest{Name: "demo", Version: "1.0.0", API: plugin.APIVersion, Capabilities: caps}
	require.NoError(t, m.Validate())
	return m
}

func TestLockRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plugins.lock")

	l, err := plugin.LoadLock(path)
	require.NoError(t, err, "a missing lock is an empty lock, not an error")
	assert.Empty(t, l.Names())

	m := manifest(t, plugin.Capabilities{ReadPaths: []string{"a/**"}})
	l.Grant(m, "digest-1")
	require.NoError(t, l.Save(path))

	reloaded, err := plugin.LoadLock(path)
	require.NoError(t, err)
	assert.Equal(t, []string{"demo"}, reloaded.Names())
	assert.Equal(t, plugin.GrantValid, reloaded.Check(m, "digest-1"))
}

// TestLockIsPrivate matters because the lock records what the user approved:
// another account being able to edit it would let them grant capabilities in
// the user's name.
func TestLockIsPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plugins.lock")
	l, err := plugin.LoadLock(path)
	require.NoError(t, err)
	l.Grant(manifest(t, plugin.Capabilities{}), "d")
	require.NoError(t, l.Save(path))

	fi, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
}

func TestCheckStates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plugins.lock")
	l, err := plugin.LoadLock(path)
	require.NoError(t, err)

	granted := manifest(t, plugin.Capabilities{ReadPaths: []string{"work/**"}})
	l.Grant(granted, "digest-1")

	t.Run("unknown plugin", func(t *testing.T) {
		other := manifest(t, plugin.Capabilities{})
		other.Name = "stranger"
		assert.Equal(t, plugin.GrantMissing, l.Check(other, "digest-1"))
	})

	// The rule that makes the digest worth recording: approving a plugin
	// once must not approve every future version of it, including one its
	// author never wrote.
	t.Run("binary changed since approval", func(t *testing.T) {
		assert.Equal(t, plugin.GrantStale, l.Check(granted, "digest-2"))
	})

	t.Run("manifest now asks for more", func(t *testing.T) {
		widened := manifest(t, plugin.Capabilities{
			ReadPaths: []string{"work/**"},
			Decrypt:   true,
		})
		assert.Equal(t, plugin.GrantWidened, l.Check(widened, "digest-1"))
	})

	// Re-prompting for something already covered would train the user to
	// approve without reading, which is worse than not prompting.
	t.Run("narrower request stays approved", func(t *testing.T) {
		narrower := manifest(t, plugin.Capabilities{ReadPaths: []string{"work/aws"}})
		assert.Equal(t, plugin.GrantValid, l.Check(narrower, "digest-1"))
	})

	t.Run("sibling subtree is not covered", func(t *testing.T) {
		sibling := manifest(t, plugin.Capabilities{ReadPaths: []string{"personal/**"}})
		assert.Equal(t, plugin.GrantWidened, l.Check(sibling, "digest-1"))
	})
}

func TestRevoke(t *testing.T) {
	l := &plugin.Lock{Version: 1, Grants: map[string]plugin.Grant{}}
	m := manifest(t, plugin.Capabilities{})
	l.Grant(m, "d")
	require.Equal(t, plugin.GrantValid, l.Check(m, "d"))

	l.Revoke("demo")
	assert.Equal(t, plugin.GrantMissing, l.Check(m, "d"))
}

func TestDigestFileDetectsAChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bin")
	require.NoError(t, os.WriteFile(path, []byte("original"), 0o700)) //nolint:gosec // a test stub.

	first, err := plugin.DigestFile(path)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(path, []byte("replaced"), 0o700)) //nolint:gosec // a test stub.
	second, err := plugin.DigestFile(path)
	require.NoError(t, err)

	assert.NotEqual(t, first, second)
}

func TestLoadLockRejectsCorruption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plugins.lock")
	require.NoError(t, os.WriteFile(path, []byte("{not json"), 0o600))

	_, err := plugin.LoadLock(path)
	assert.ErrorContains(t, err, "corrupt",
		"a damaged lock must be reported, never treated as no grants at all")
}
