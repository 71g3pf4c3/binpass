package remote

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemRemote_PutGet(t *testing.T) {
	m := NewMemRemote(MemOptions{})
	ctx := context.Background()

	rev, err := m.Put(ctx, "a.gpg", bytes.NewReader([]byte("hello")), "")
	require.NoError(t, err)
	assert.NotEmpty(t, rev)

	rc, gotRev, err := m.Get(ctx, "a.gpg")
	require.NoError(t, err)
	defer rc.Close()
	data, err := io.ReadAll(rc)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(data))
	assert.Equal(t, rev, gotRev)
}

func TestMemRemote_List(t *testing.T) {
	m := NewMemRemote(MemOptions{})
	ctx := context.Background()

	_, _ = m.Put(ctx, "x.gpg", bytes.NewReader([]byte("1")), "")
	_, _ = m.Put(ctx, "y.gpg", bytes.NewReader([]byte("2")), "")

	files, err := m.List(ctx)
	require.NoError(t, err)
	assert.Len(t, files, 2)
	paths := map[string]bool{}
	for _, f := range files {
		paths[f.Path] = true
		assert.Equal(t, int64(1), f.Size)
		assert.NotEmpty(t, f.Rev)
	}
	assert.True(t, paths["x.gpg"])
	assert.True(t, paths["y.gpg"])
}

func TestMemRemote_Delete(t *testing.T) {
	m := NewMemRemote(MemOptions{})
	ctx := context.Background()

	_, _ = m.Put(ctx, "a.gpg", bytes.NewReader([]byte("data")), "")
	require.NoError(t, m.Delete(ctx, "a.gpg", ""))

	_, _, err := m.Get(ctx, "a.gpg")
	assert.Error(t, err)
}

func TestMemRemote_ConditionalWrite(t *testing.T) {
	m := NewMemRemote(MemOptions{})
	ctx := context.Background()

	rev, err := m.Put(ctx, "a.gpg", bytes.NewReader([]byte("v1")), "")
	require.NoError(t, err)

	// Wrong expectRev should fail.
	_, err = m.Put(ctx, "a.gpg", bytes.NewReader([]byte("v2")), "wrong-rev")
	assert.Error(t, err)

	// Correct expectRev should succeed.
	newRev, err := m.Put(ctx, "a.gpg", bytes.NewReader([]byte("v2")), rev)
	require.NoError(t, err)
	assert.NotEqual(t, rev, newRev)
}

func TestMemRemote_Rename(t *testing.T) {
	m := NewMemRemote(MemOptions{})
	ctx := context.Background()

	_, _ = m.Put(ctx, "old.gpg", bytes.NewReader([]byte("data")), "")
	require.NoError(t, m.Rename(ctx, "old.gpg", "new.gpg"))

	_, _, err := m.Get(ctx, "old.gpg")
	assert.Error(t, err)

	rc, _, err := m.Get(ctx, "new.gpg")
	require.NoError(t, err)
	defer rc.Close()
	data, _ := io.ReadAll(rc)
	assert.Equal(t, "data", string(data))
}

func TestMemRemote_Caps(t *testing.T) {
	m := NewMemRemote(MemOptions{
		Caps: Caps{Atomic: true, History: true},
	})
	c := m.Caps()
	assert.True(t, c.Atomic)
	assert.True(t, c.History)
	assert.False(t, c.Locking)
}

func TestMemRemote_NameLockClose(t *testing.T) {
	m := NewMemRemote(MemOptions{Name: "test"})
	ctx := context.Background()

	assert.Equal(t, "test", m.Name())

	lock, err := m.Lock(ctx)
	require.NoError(t, err)
	require.NoError(t, lock.Unlock(ctx))

	require.NoError(t, m.Close())
}

func TestMemRemote_DeleteConditional(t *testing.T) {
	m := NewMemRemote(MemOptions{})
	ctx := context.Background()

	rev, err := m.Put(ctx, "a.gpg", bytes.NewReader([]byte("data")), "")
	require.NoError(t, err)

	// Wrong rev should fail.
	err = m.Delete(ctx, "a.gpg", "wrong-rev")
	assert.Error(t, err)

	// Correct rev should succeed.
	err = m.Delete(ctx, "a.gpg", rev)
	require.NoError(t, err)
}

func TestMemRemote_DeleteNotFound(t *testing.T) {
	m := NewMemRemote(MemOptions{})
	ctx := context.Background()

	err := m.Delete(ctx, "nonexistent.gpg", "")
	assert.Error(t, err)
}

func TestMemRemote_RenameNotFound(t *testing.T) {
	m := NewMemRemote(MemOptions{})
	ctx := context.Background()

	err := m.Rename(ctx, "nonexistent.gpg", "new.gpg")
	assert.Error(t, err)
}

func TestMemRemote_GetNotFound(t *testing.T) {
	m := NewMemRemote(MemOptions{})
	ctx := context.Background()

	_, _, err := m.Get(ctx, "nonexistent.gpg")
	assert.Error(t, err)
}

func TestNoopUnlock(t *testing.T) {
	var u NoopUnlock
	require.NoError(t, u.Unlock(context.Background()))
}
