package secretservice_test

import (
	"encoding/json"
	"path"
	"strings"
	"testing"

	"github.com/71g3pf4c3/binpass/pkg/secret"
	"github.com/71g3pf4c3/binpass/pkg/secretservice"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// memStore is an in-memory PassStore. It stands in for the encrypted store,
// and — because it keeps what was written verbatim — it is also how the
// privacy tests inspect exactly what would have reached the disk.
type memStore struct {
	entries map[string]string
}

func newMemStore() *memStore { return &memStore{entries: map[string]string{}} }

func (m *memStore) Get(name string) (*secret.Secret, error) {
	raw, ok := m.entries[name]
	if !ok {
		return nil, assertNotExist{name}
	}
	return secret.Parse([]byte(raw)), nil
}

func (m *memStore) Set(name string, sec *secret.Secret) error {
	m.entries[name] = sec.String()
	return nil
}

func (m *memStore) List(sub string) ([]string, error) {
	var out []string
	for k := range m.entries {
		if sub == "" || strings.HasPrefix(k, sub+"/") {
			out = append(out, k)
		}
	}
	return out, nil
}

func (m *memStore) Remove(name string) error {
	if _, ok := m.entries[name]; !ok {
		return assertNotExist{name}
	}
	delete(m.entries, name)
	return nil
}

func (m *memStore) Exists(name string) bool {
	_, ok := m.entries[name]
	return ok
}

type assertNotExist struct{ name string }

func (e assertNotExist) Error() string { return "not found: " + e.name }

// newTestStore returns a Store over an empty in-memory password store.
func newTestStore(t *testing.T) (*secretservice.Store, *memStore) {
	t.Helper()
	mem := newMemStore()
	return secretservice.NewStore(mem, []byte("test seed")), mem
}

func TestCreateAndReadAnItem(t *testing.T) {
	s, _ := newTestStore(t)

	created, err := s.CreateItem("login", &secretservice.Item{
		Label:      "GitHub token",
		Secret:     "correct-horse-battery-staple",
		Attributes: map[string]string{"server": "github.com", "username": "alice"},
	}, false)
	require.NoError(t, err)
	require.NotEmpty(t, created.ID)

	got, err := s.Item("login", created.ID)
	require.NoError(t, err)
	assert.Equal(t, "GitHub token", got.Label)
	assert.Equal(t, "correct-horse-battery-staple", got.Secret)
	assert.Equal(t, "github.com", got.Attributes["server"])
	assert.Equal(t, "alice", got.Attributes["username"])
	assert.False(t, got.Created.IsZero())
}

// TestStoredItemIsAnOrdinaryPassEntry is the compatibility promise: an item
// a browser wrote must be readable with `pass show`, not a private format
// that happens to live in the same directory.
func TestStoredItemIsAnOrdinaryPassEntry(t *testing.T) {
	s, mem := newTestStore(t)

	created, err := s.CreateItem("login", &secretservice.Item{
		Label:      "GitHub token",
		Secret:     "hunter2",
		Attributes: map[string]string{"server": "github.com"},
	}, false)
	require.NoError(t, err)

	raw := mem.entries[path.Join("secret-service", "login", created.ID)]
	lines := strings.Split(strings.TrimRight(raw, "\n"), "\n")

	// pass's own rule: the password is the first line, and nothing else.
	assert.Equal(t, "hunter2", lines[0])
	assert.Contains(t, raw, "label: GitHub token")
	assert.Contains(t, raw, "attr.server: github.com")
}

// TestAttributesNeverReachTheFilename is the point of the whole design. The
// file name is the one part of an item that stays visible to a git host or a
// cloud drive, so it must carry nothing.
func TestAttributesNeverReachTheFilename(t *testing.T) {
	s, mem := newTestStore(t)

	_, err := s.CreateItem("login", &secretservice.Item{
		Label:  "Bank",
		Secret: "s3cret",
		Attributes: map[string]string{
			"server":      "bank.example.com",
			"username":    "alice",
			"application": "firefox",
		},
	}, false)
	require.NoError(t, err)

	for name := range mem.entries {
		for _, leak := range []string{"bank.example.com", "alice", "firefox", "Bank"} {
			assert.NotContains(t, name, leak,
				"an entry name must not disclose %q: names are visible to whoever the store syncs with", leak)
		}
	}
}

// TestIndexDoesNotDiscloseAttributeValues covers the file the sync provider
// sees in full. Its contents are keyed hashes, so it must contain no
// attribute name or value in the clear.
func TestIndexDoesNotDiscloseAttributeValues(t *testing.T) {
	s, mem := newTestStore(t)

	_, err := s.CreateItem("login", &secretservice.Item{
		Secret: "s3cret",
		Attributes: map[string]string{
			"server":   "bank.example.com",
			"username": "alice",
		},
	}, false)
	require.NoError(t, err)

	raw, ok := mem.entries[path.Join("secret-service", ".index")]
	require.True(t, ok, "an index must be written")

	for _, leak := range []string{"bank.example.com", "alice", "server", "username", "s3cret"} {
		assert.NotContains(t, raw, leak,
			"the index must not disclose %q; that is the difference from pass-secret-service", leak)
	}

	// It must still be a well-formed index rather than merely opaque.
	var ix secretservice.Index
	require.NoError(t, json.Unmarshal([]byte(raw), &ix))
	assert.NotEmpty(t, ix.Entries)
}

func TestSearchMatchesEveryPair(t *testing.T) {
	s, _ := newTestStore(t)

	mustCreate(t, s, "login", "github", map[string]string{"server": "github.com", "username": "alice"})
	mustCreate(t, s, "login", "gitlab", map[string]string{"server": "gitlab.com", "username": "alice"})
	mustCreate(t, s, "login", "other", map[string]string{"server": "github.com", "username": "bob"})

	// One pair: everything carrying it.
	got, err := s.Search("login", map[string]string{"server": "github.com"})
	require.NoError(t, err)
	assert.Len(t, got, 2)

	// Both pairs: the intersection, not the union.
	got, err = s.Search("login", map[string]string{"server": "github.com", "username": "alice"})
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "github", got[0].Secret)

	// A pair nobody carries matches nothing, even alongside one they do.
	got, err = s.Search("login", map[string]string{"server": "github.com", "username": "nobody"})
	require.NoError(t, err)
	assert.Empty(t, got)
}

// TestSearchIsExactNotPrefix guards the assumption the blind index rests on:
// the specification matches attribute values exactly, and a hash cannot do
// anything else. A client expecting prefix search must get nothing rather
// than something plausible.
func TestSearchIsExactNotPrefix(t *testing.T) {
	s, _ := newTestStore(t)
	mustCreate(t, s, "login", "x", map[string]string{"server": "github.com"})

	for _, q := range []string{"github", "github.co", "GITHUB.COM", "github.com "} {
		got, err := s.Search("login", map[string]string{"server": q})
		require.NoError(t, err)
		assert.Empty(t, got, "%q must not match github.com", q)
	}
}

func TestCreateWithoutReplaceReturnsTheExistingItem(t *testing.T) {
	s, _ := newTestStore(t)
	attrs := map[string]string{"server": "github.com", "username": "alice"}

	first := mustCreate(t, s, "login", "first", attrs)
	second, err := s.CreateItem("login", &secretservice.Item{Secret: "second", Attributes: attrs}, false)
	require.NoError(t, err)

	// The specification says a duplicate create returns the original rather
	// than storing a second copy of the same account.
	assert.Equal(t, first.ID, second.ID)
	assert.Equal(t, "first", second.Secret, "the stored secret must not have been overwritten")
}

func TestCreateWithReplaceUpdatesInPlace(t *testing.T) {
	s, _ := newTestStore(t)
	attrs := map[string]string{"server": "github.com", "username": "alice"}

	first := mustCreate(t, s, "login", "old", attrs)
	second, err := s.CreateItem("login", &secretservice.Item{Secret: "new", Attributes: attrs}, true)
	require.NoError(t, err)

	assert.Equal(t, first.ID, second.ID, "replacing must reuse the item, not orphan it")
	// Compared by second: the stored form is a Unix timestamp, so the
	// in-memory value is deliberately more precise than the file.
	assert.Equal(t, first.Created.Unix(), second.Created.Unix(),
		"the creation time survives an update")

	got, err := s.Item("login", first.ID)
	require.NoError(t, err)
	assert.Equal(t, "new", got.Secret)

	items, err := s.Items("login")
	require.NoError(t, err)
	assert.Len(t, items, 1, "replacing must not leave the old item behind")
}

// TestCreateDoesNotOverwriteASupersetOfItsAttributes covers a way to lose a
// password: an item carrying more attributes than the query is a different
// account, not the one being updated.
func TestCreateDoesNotOverwriteASupersetOfItsAttributes(t *testing.T) {
	s, _ := newTestStore(t)

	broad := mustCreate(t, s, "login", "broad", map[string]string{
		"server": "github.com", "username": "alice", "port": "443",
	})
	narrow, err := s.CreateItem("login", &secretservice.Item{
		Secret:     "narrow",
		Attributes: map[string]string{"server": "github.com", "username": "alice"},
	}, true)
	require.NoError(t, err)

	assert.NotEqual(t, broad.ID, narrow.ID, "these describe different accounts")

	got, err := s.Item("login", broad.ID)
	require.NoError(t, err)
	assert.Equal(t, "broad", got.Secret, "the existing password must survive")
}

func TestDeleteRemovesFromTheIndexToo(t *testing.T) {
	s, _ := newTestStore(t)
	attrs := map[string]string{"server": "github.com"}
	it := mustCreate(t, s, "login", "x", attrs)

	require.NoError(t, s.DeleteItem("login", it.ID))

	got, err := s.Search("login", attrs)
	require.NoError(t, err)
	assert.Empty(t, got, "a deleted item must not still be findable")

	_, err = s.Item("login", it.ID)
	assert.ErrorIs(t, err, secretservice.ErrNotFound)
}

func TestDeleteAnItemThatIsNotThere(t *testing.T) {
	s, _ := newTestStore(t)
	assert.ErrorIs(t, s.DeleteItem("login", "nope"), secretservice.ErrNotFound)
}

func TestCollectionsAndItems(t *testing.T) {
	s, _ := newTestStore(t)
	mustCreate(t, s, "login", "a", map[string]string{"k": "1"})
	mustCreate(t, s, "work", "b", map[string]string{"k": "2"})

	cols, err := s.Collections()
	require.NoError(t, err)
	assert.Equal(t, []string{"login", "work"}, cols)

	items, err := s.Items("login")
	require.NoError(t, err)
	assert.Len(t, items, 1)
}

func TestEmptyStoreIsAnEmptyKeyring(t *testing.T) {
	s, _ := newTestStore(t)

	// A store nothing has written to yet must read as empty rather than as
	// an error: that is a fresh keyring, not a broken one.
	cols, err := s.Collections()
	require.NoError(t, err)
	assert.Empty(t, cols)

	items, err := s.Items("login")
	require.NoError(t, err)
	assert.Empty(t, items)
}

// TestReindexRepairsADamagedIndex covers the recovery path: the items are
// the truth, and the index is derived, so it can always be rebuilt.
func TestReindexRepairsADamagedIndex(t *testing.T) {
	s, mem := newTestStore(t)
	attrs := map[string]string{"server": "github.com"}
	mustCreate(t, s, "login", "x", attrs)

	// Simulate an index that drifted: a sync brought items from another
	// machine without the index, or someone deleted the file.
	delete(mem.entries, path.Join("secret-service", ".index"))
	fresh := secretservice.NewStore(mem, []byte("test seed"))

	n, err := fresh.Reindex()
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	got, err := fresh.Search("login", attrs)
	require.NoError(t, err)
	assert.Len(t, got, 1)
}

// TestSearchSurvivesAnItemDeletedByHand: the index names an item that is no
// longer there. Searching must skip it rather than fail, because a user
// deleting an entry with `binpass rm` is entitled to do that.
func TestSearchSurvivesAnItemDeletedByHand(t *testing.T) {
	s, mem := newTestStore(t)
	attrs := map[string]string{"server": "github.com"}
	it := mustCreate(t, s, "login", "x", attrs)

	delete(mem.entries, path.Join("secret-service", "login", it.ID))

	got, err := s.Search("login", attrs)
	require.NoError(t, err)
	assert.Empty(t, got)
}

// TestTheIndexIsUselessWithoutTheKey states the security property plainly:
// an index taken from a synchronised store tells its holder nothing unless
// they also hold the key, which never leaves the machine.
func TestTheIndexIsUselessWithoutTheKey(t *testing.T) {
	mem := newMemStore()
	mine := secretservice.NewStore(mem, []byte("my seed"))
	attrs := map[string]string{"server": "github.com", "username": "alice"}
	mustCreate(t, mine, "login", "x", attrs)

	// Someone with the files but a different key.
	theirs := secretservice.NewStore(mem, []byte("a guess"))
	got, err := theirs.Search("login", attrs)
	require.NoError(t, err)
	assert.Empty(t, got, "the index must not answer to a key it was not built with")

	// And the same key reproduces the same lookups, which is what makes an
	// index survive being synchronised between machines.
	same := secretservice.NewStore(mem, []byte("my seed"))
	got, err = same.Search("login", attrs)
	require.NoError(t, err)
	assert.Len(t, got, 1)
}

// mustCreate stores an item with the given secret and attributes.
func mustCreate(t *testing.T, s *secretservice.Store, collection, secretValue string, attrs map[string]string) *secretservice.Item {
	t.Helper()
	it, err := s.CreateItem(collection, &secretservice.Item{
		Secret:     secretValue,
		Attributes: attrs,
	}, false)
	require.NoError(t, err)
	return it
}
