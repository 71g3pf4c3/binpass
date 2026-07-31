package manifest

import (
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestObjectIDStable(t *testing.T) {
	a := ObjectID([]byte("hello"))
	b := ObjectID([]byte("hello"))
	c := ObjectID([]byte("world"))
	assert.Equal(t, a, b)
	assert.NotEqual(t, a, c)
	assert.Contains(t, a, "b3:")
}

func TestCanonicalDeterministic(t *testing.T) {
	m := New("store-1")
	m.Entries["b"] = Entry{Object: "b3:1", Kind: KindSecret, Version: VersionVector{"d": 1}}
	m.Entries["a"] = Entry{Object: "b3:2", Kind: KindSecret, Version: VersionVector{"d": 2}}

	c1, err := Canonical(m)
	require.NoError(t, err)
	c2, err := Canonical(m.Clone())
	require.NoError(t, err)
	assert.Equal(t, c1, c2)
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	m := New("store-1")
	m.Generation = 5
	m.Entries["x"] = Entry{Object: "b3:1", Kind: KindSecret, Version: VersionVector{"d": 1}}

	signed, err := Sign(m, priv)
	require.NoError(t, err)

	got, err := Verify(signed, pub, 0)
	require.NoError(t, err)
	assert.Equal(t, uint64(5), got.Generation)
	assert.Equal(t, "store-1", got.StoreID)
}

func TestVerifyRejectsTamper(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	m := New("store-1")
	signed, _ := Sign(m, priv)
	signed.Manifest = append(signed.Manifest, ' ')
	_, err := Verify(signed, nil, 0)
	assert.Error(t, err)
}

func TestVerifyRejectsRollback(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	m := New("store-1")
	m.Generation = 3
	signed, _ := Sign(m, priv)
	_, err := Verify(signed, nil, 5) // require at least gen 5
	assert.Error(t, err)
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	otherPub, _, _ := ed25519.GenerateKey(nil)
	m := New("store-1")
	signed, _ := Sign(m, priv)
	_, err := Verify(signed, otherPub, 0)
	assert.Error(t, err)
}

func TestObjectIDsDedup(t *testing.T) {
	m := New("s")
	m.Entries["a"] = Entry{Object: "b3:1"}
	m.Entries["b"] = Entry{Object: "b3:1"}
	m.Entries["c"] = Entry{Object: "b3:2", Deleted: true}
	ids := m.ObjectIDs()
	assert.ElementsMatch(t, []string{"b3:1"}, ids)
}

func FuzzCanonicalRoundTrip(f *testing.F) {
	f.Add("store", uint64(1), "path", "b3:abc")
	f.Fuzz(func(t *testing.T, storeID string, gen uint64, path, oid string) {
		m := New(storeID)
		m.Generation = gen
		if path != "" {
			m.Entries[path] = Entry{Object: oid, Kind: KindSecret, Version: VersionVector{"d": 1}}
		}
		c, err := Canonical(m)
		if err != nil {
			return
		}
		// Canonicalising twice must be byte-identical.
		c2, err := Canonical(m.Clone())
		require.NoError(t, err)
		require.Equal(t, c, c2)
	})
}
