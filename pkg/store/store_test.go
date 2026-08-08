package store_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/71g3pf4c3/binpass/pkg/crypto"
	"github.com/71g3pf4c3/binpass/pkg/secret"
	"github.com/71g3pf4c3/binpass/pkg/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixture is a store wired to a single age backend with a known key.
type fixture struct {
	*store.Store
	// dir is the store root.
	dir string
	// recipient is the key entries are encrypted to by default.
	recipient crypto.Recipient
}

// newFixture builds an initialised age store in a temporary directory.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	backend := crypto.NewAge(dir, func() ([]age.Identity, error) {
		return []age.Identity{id}, nil
	})
	s, err := store.New(store.Options{Dir: dir, Backends: []crypto.Crypto{backend}})
	require.NoError(t, err)

	rcp := crypto.Recipient(id.Recipient().String())
	require.NoError(t, s.Init("", []crypto.Recipient{rcp}))
	return &fixture{Store: s, dir: dir, recipient: rcp}
}

// set stores an entry, failing the test on error.
func (f *fixture) set(t *testing.T, name, content string) {
	t.Helper()
	require.NoError(t, f.Set(name, secret.Parse([]byte(content))))
}

func TestInitAndInitialised(t *testing.T) {
	f := newFixture(t)
	assert.True(t, f.Initialised())

	data, err := os.ReadFile(filepath.Join(f.dir, ".age-recipients"))
	require.NoError(t, err)
	assert.Equal(t, f.recipient.String()+"\n", string(data))
}

func TestNotInitialised(t *testing.T) {
	dir := t.TempDir()
	s, err := store.New(store.Options{
		Dir:      dir,
		Backends: []crypto.Crypto{crypto.NewAge(dir, nil)},
	})
	require.NoError(t, err)
	assert.False(t, s.Initialised())
}

func TestSetGetRoundTrip(t *testing.T) {
	f := newFixture(t)
	f.set(t, "github.com/alice", "hunter2\nurl: https://github.com\n")

	got, err := f.Get("github.com/alice")
	require.NoError(t, err)
	assert.Equal(t, "hunter2", got.Password())

	url, ok := got.Field("url")
	require.True(t, ok)
	assert.Equal(t, "https://github.com", url)
}

func TestGetMissing(t *testing.T) {
	_, err := newFixture(t).Get("nope")
	assert.ErrorIs(t, err, store.ErrNotFound)
}

func TestSetOverwritesAndSetNewRefuses(t *testing.T) {
	f := newFixture(t)
	f.set(t, "entry", "first\n")
	f.set(t, "entry", "second\n")

	got, err := f.Get("entry")
	require.NoError(t, err)
	assert.Equal(t, "second", got.Password())

	err = f.SetNew("entry", secret.New("third", ""))
	assert.ErrorIs(t, err, store.ErrExists)
}

func TestSetWritesCiphertext(t *testing.T) {
	f := newFixture(t)
	f.set(t, "entry", "hunter2\n")

	raw, err := os.ReadFile(filepath.Join(f.dir, "entry.age"))
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "hunter2")
}

func TestList(t *testing.T) {
	f := newFixture(t)
	f.set(t, "b", "x\n")
	f.set(t, "a", "x\n")
	f.set(t, "sub/c", "x\n")

	names, err := f.List("")
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b", "sub/c"}, names)

	names, err = f.List("sub")
	require.NoError(t, err)
	assert.Equal(t, []string{"sub/c"}, names)
}

func TestRemove(t *testing.T) {
	f := newFixture(t)
	f.set(t, "sub/entry", "x\n")
	require.NoError(t, f.Remove("sub/entry"))
	assert.False(t, f.Exists("sub/entry"))
	assert.ErrorIs(t, f.Remove("sub/entry"), store.ErrNotFound)
}

func TestRemoveDirRefusesRoot(t *testing.T) {
	f := newFixture(t)
	assert.Error(t, f.RemoveDir(""))
	assert.True(t, f.Initialised(), "the store survives an attempt to remove its root")
}

func TestMoveEntry(t *testing.T) {
	f := newFixture(t)
	f.set(t, "old", "hunter2\n")
	require.NoError(t, f.Move("old", "new"))

	assert.False(t, f.Exists("old"))
	got, err := f.Get("new")
	require.NoError(t, err)
	assert.Equal(t, "hunter2", got.Password())
}

func TestMoveIntoExistingDirectory(t *testing.T) {
	f := newFixture(t)
	f.set(t, "entry", "hunter2\n")
	f.set(t, "folder/other", "x\n")
	require.NoError(t, f.Move("entry", "folder"))

	got, err := f.Get("folder/entry")
	require.NoError(t, err)
	assert.Equal(t, "hunter2", got.Password(), "moving onto a folder moves into it")
}

func TestMoveReencryptsForNewRecipients(t *testing.T) {
	f := newFixture(t)
	f.set(t, "entry", "hunter2\n")

	// A subtree shared with a different key: the moved entry must end up
	// readable by that key, not the old one.
	other, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	require.NoError(t, f.Init("bank", []crypto.Recipient{crypto.Recipient(other.Recipient().String())}))
	require.NoError(t, f.Move("entry", "bank/entry"))

	raw, err := os.ReadFile(filepath.Join(f.dir, "bank", "entry.age"))
	require.NoError(t, err)

	decrypted := decryptWith(t, raw, other)
	assert.Equal(t, "hunter2\n", decrypted)
}

func TestCopyKeepsSource(t *testing.T) {
	f := newFixture(t)
	f.set(t, "entry", "hunter2\n")
	require.NoError(t, f.Copy("entry", "copy"))

	assert.True(t, f.Exists("entry"))
	got, err := f.Get("copy")
	require.NoError(t, err)
	assert.Equal(t, "hunter2", got.Password())
}

func TestMoveDirectory(t *testing.T) {
	f := newFixture(t)
	f.set(t, "src/one", "1\n")
	f.set(t, "src/deep/two", "2\n")
	require.NoError(t, f.Move("src", "dst"))

	names, err := f.List("")
	require.NoError(t, err)
	assert.Equal(t, []string{"dst/deep/two", "dst/one"}, names)
}

func TestReencryptAfterRecipientChange(t *testing.T) {
	f := newFixture(t)
	f.set(t, "entry", "hunter2\n")

	next, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	require.NoError(t, crypto.WriteRecipients(
		filepath.Join(f.dir, ".age-recipients"),
		[]crypto.Recipient{crypto.Recipient(next.Recipient().String())},
	))
	require.NoError(t, f.Reencrypt("", nil))

	raw, err := os.ReadFile(filepath.Join(f.dir, "entry.age"))
	require.NoError(t, err)
	assert.Equal(t, "hunter2\n", decryptWith(t, raw, next))
}

func TestFind(t *testing.T) {
	f := newFixture(t)
	f.set(t, "github.com/alice", "x\n")
	f.set(t, "gitlab.com/bob", "x\n")
	f.set(t, "bank/tinkoff", "x\n")

	got, err := f.Find([]string{"git"})
	require.NoError(t, err)
	assert.Equal(t, []string{"github.com/alice", "gitlab.com/bob"}, got)

	got, err = f.Find([]string{"ALICE"})
	require.NoError(t, err)
	assert.Equal(t, []string{"github.com/alice"}, got, "search is case-insensitive")
}

func TestGrep(t *testing.T) {
	f := newFixture(t)
	f.set(t, "one", "pw\nurl: https://example.com\n")
	f.set(t, "two", "pw\nurl: https://other.org\n")

	matches, err := f.Grep("", func(line string) bool {
		return line == "url: https://example.com"
	})
	require.NoError(t, err)
	require.Len(t, matches, 1)
	assert.Equal(t, "one", matches[0].Name)
	assert.Equal(t, []string{"url: https://example.com"}, matches[0].Lines)
}

func TestRecipients(t *testing.T) {
	f := newFixture(t)
	f.set(t, "sub/entry", "x\n")

	got, err := f.Recipients("sub/entry")
	require.NoError(t, err)
	assert.Equal(t, []crypto.Recipient{f.recipient}, got)
}

func TestNewRequiresBackend(t *testing.T) {
	_, err := store.New(store.Options{Dir: t.TempDir()})
	assert.Error(t, err)
}

// decryptWith decrypts raw age ciphertext with a known identity.
func decryptWith(t *testing.T, raw []byte, id age.Identity) string {
	t.Helper()
	dir := t.TempDir()
	backend := crypto.NewAge(dir, func() ([]age.Identity, error) {
		return []age.Identity{id}, nil
	})
	out, err := backend.Decrypt(bytes.NewReader(raw))
	require.NoError(t, err)
	return string(out)
}
