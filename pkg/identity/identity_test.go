package identity_test

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/71g3pf4c3/binpass/pkg/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeKey writes a fresh age identity file and returns the key it holds.
func writeKey(t *testing.T, path string) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte(id.String()+"\n"), 0o600))
	return id
}

func TestExplicitIdentityWins(t *testing.T) {
	dir := t.TempDir()
	explicit := writeKey(t, filepath.Join(dir, "explicit.txt"))
	writeKey(t, filepath.Join(dir, "fallback.txt"))

	r := &identity.Resolver{
		Explicit: filepath.Join(dir, "explicit.txt"),
		Files:    []string{filepath.Join(dir, "fallback.txt")},
	}
	ids, err := r.Load()
	require.NoError(t, err)
	require.Len(t, ids, 1, "an explicit identity is never widened by fallbacks")
	assert.Equal(t, explicit.Recipient().String(), ids[0].(*age.X25519Identity).Recipient().String())
}

func TestFilesAreTriedInOrder(t *testing.T) {
	dir := t.TempDir()
	first := writeKey(t, filepath.Join(dir, "first.txt"))
	second := writeKey(t, filepath.Join(dir, "second.txt"))

	r := &identity.Resolver{Files: []string{
		filepath.Join(dir, "missing.txt"),
		filepath.Join(dir, "first.txt"),
		filepath.Join(dir, "second.txt"),
	}}
	ids, err := r.Load()
	require.NoError(t, err)
	require.Len(t, ids, 2, "missing files are skipped, present ones accumulate")
	assert.Equal(t, first.Recipient().String(), ids[0].(*age.X25519Identity).Recipient().String())
	assert.Equal(t, second.Recipient().String(), ids[1].(*age.X25519Identity).Recipient().String())
}

func TestNoIdentity(t *testing.T) {
	r := &identity.Resolver{Files: []string{filepath.Join(t.TempDir(), "nope.txt")}}
	_, err := r.Load()
	assert.ErrorIs(t, err, identity.ErrNone)
}

func TestMissingExplicitIsAnError(t *testing.T) {
	r := &identity.Resolver{Explicit: filepath.Join(t.TempDir(), "nope.txt")}
	_, err := r.Load()
	assert.Error(t, err)
	assert.NotErrorIs(t, err, identity.ErrNone, "an explicit path that does not exist is a hard error")
}

func TestBrokenFileIsAnError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "broken.txt")
	require.NoError(t, os.WriteFile(path, []byte("AGE-SECRET-KEY-1NOTVALID\n"), 0o600))

	_, err := (&identity.Resolver{Files: []string{path}}).Load()
	assert.Error(t, err, "a present but unparsable key file must not be skipped silently")
}

func TestParseIdentitiesSkipsCommentsAndBlanks(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	data := "# my key\n\n" + id.String() + "\n\n"
	ids, kind, err := identity.ParseIdentities(data, nil)
	require.NoError(t, err)
	assert.Equal(t, identity.KindFile, kind)
	require.Len(t, ids, 1)
}

func TestParseIdentitiesAcceptsPluginLines(t *testing.T) {
	// A plugin line is resolved without executing the plugin binary, so this
	// works even with no token attached.
	ids, kind, err := identity.ParseIdentities("AGE-PLUGIN-YUBIKEY-1QYPQXPQTZJ3QV\n", nil)
	require.NoError(t, err)
	assert.Equal(t, identity.KindPlugin, kind)
	assert.Len(t, ids, 1)
}

func TestSourcesReportsOrigin(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.txt")
	writeKey(t, path)

	sources, err := (&identity.Resolver{Files: []string{path}}).Sources()
	require.NoError(t, err)
	require.Len(t, sources, 1)
	assert.Equal(t, path, sources[0].Path)
	assert.Equal(t, identity.KindFile, sources[0].Kind)
}

func TestNewResolverReadsEnvironment(t *testing.T) {
	t.Setenv("BINPASS_IDENTITY", "/from/env")
	assert.Equal(t, "/from/env", identity.NewResolver("").Explicit)
	assert.Equal(t, "/from/flag", identity.NewResolver("/from/flag").Explicit, "the flag beats the environment")
}

func TestDefaultFilesOrder(t *testing.T) {
	t.Setenv("BINPASS_DATA_DIR", "/data")
	t.Setenv("XDG_CONFIG_HOME", "/config")
	t.Setenv("PASSAGE_IDENTITIES_FILE", "/passage/ids")

	assert.Equal(t, []string{
		filepath.Join("/data", "identities.age"),
		filepath.Join("/config", "binpass", "identities.age"),
		filepath.Join("/config", "age", "keys.txt"),
		"/passage/ids",
	}, identity.DefaultFiles())
}

// TestDefaultFilesCoversWhereInitWrites guards the bug where init created the
// key under the config directory while the resolver only looked in the data
// directory, so a store the tool had just set up could not be opened.
func TestDefaultFilesCoversWhereInitWrites(t *testing.T) {
	t.Setenv("BINPASS_DATA_DIR", "/data")
	t.Setenv("XDG_CONFIG_HOME", "/config")

	assert.Contains(t, identity.DefaultFiles(),
		filepath.Join("/config", "binpass", "identities.age"))
}
