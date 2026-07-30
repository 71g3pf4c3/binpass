package store

import (
	"testing"

	"filippo.io/age"
	"github.com/71g3pf4c3/binpass/pkg/crypto"
	"github.com/71g3pf4c3/binpass/pkg/secret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestStore builds a store in a temp dir with a fresh identity.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	c := crypto.NewAge([]age.Identity{id})
	st := New(t.TempDir(), c)
	require.NoError(t, st.Init([]string{id.Recipient().String()}))
	return st
}

func TestSetGet(t *testing.T) {
	st := newTestStore(t)
	require.NoError(t, st.SetRaw("github.com/alice", []byte("hunter2\n")))
	assert.True(t, st.Exists("github.com/alice"))

	sec, err := st.Get("github.com/alice")
	require.NoError(t, err)
	assert.Equal(t, "hunter2", sec.Password)
}

func TestGetNotFound(t *testing.T) {
	st := newTestStore(t)
	_, err := st.Get("nope")
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestMoveCopyRemove(t *testing.T) {
	st := newTestStore(t)
	require.NoError(t, st.SetRaw("a", []byte("pw\n")))

	require.NoError(t, st.Copy("a", "b", false))
	assert.True(t, st.Exists("b"))

	require.NoError(t, st.Move("a", "c", false))
	assert.False(t, st.Exists("a"))
	assert.True(t, st.Exists("c"))

	err := st.Copy("b", "c", false)
	assert.ErrorIs(t, err, ErrExists)

	require.NoError(t, st.Remove("c"))
	assert.False(t, st.Exists("c"))
}

func TestListFindGrep(t *testing.T) {
	st := newTestStore(t)
	require.NoError(t, st.SetRaw("github.com/alice", []byte("secret1\n")))
	require.NoError(t, st.SetRaw("gitlab.com/bob", []byte("secret2\n")))

	names, err := st.List()
	require.NoError(t, err)
	assert.Equal(t, []string{"github.com/alice", "gitlab.com/bob"}, names)

	found, err := st.Find("alice")
	require.NoError(t, err)
	assert.Equal(t, []string{"github.com/alice"}, found)

	matches, err := st.Grep("secret2")
	require.NoError(t, err)
	require.Len(t, matches, 1)
	assert.Equal(t, "gitlab.com/bob", matches[0].Name)
}

func TestReencrypt(t *testing.T) {
	st := newTestStore(t)
	require.NoError(t, st.SetRaw("a", []byte("pw\n")))
	require.NoError(t, st.Reencrypt())
	sec, err := st.Get("a")
	require.NoError(t, err)
	assert.Equal(t, "pw", sec.Password)
}

func TestSetTypedSecret(t *testing.T) {
	st := newTestStore(t)
	sec := &secret.Secret{Kind: secret.KindCard}
	sec.Set("Bank", "Tinkoff")
	require.NoError(t, st.Set("bank/t", sec))

	got, err := st.Get("bank/t")
	require.NoError(t, err)
	assert.Equal(t, secret.KindCard, got.Kind)
	bank, _ := got.Get("Bank")
	assert.Equal(t, "Tinkoff", bank)
}
