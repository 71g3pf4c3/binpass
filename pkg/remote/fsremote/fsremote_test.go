package fsremote

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"io"
	"testing"

	"github.com/71g3pf4c3/binpass/pkg/manifest"
	"github.com/71g3pf4c3/binpass/pkg/remote"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManifestNotFound(t *testing.T) {
	f, err := New(t.TempDir())
	require.NoError(t, err)
	_, err = f.Manifest(context.Background())
	assert.ErrorIs(t, err, remote.ErrNotFound)
}

func TestCommitAndGetManifest(t *testing.T) {
	f, err := New(t.TempDir())
	require.NoError(t, err)
	ctx := context.Background()

	_, priv, _ := ed25519.GenerateKey(nil)
	m := manifest.New("s")
	m.Generation = 1
	signed, err := manifest.Sign(m, priv)
	require.NoError(t, err)

	require.NoError(t, f.CommitManifest(ctx, signed, 0))

	got, err := f.Manifest(ctx)
	require.NoError(t, err)
	assert.Equal(t, signed.Manifest, got.Manifest)
}

func TestCommitCASConflict(t *testing.T) {
	f, err := New(t.TempDir())
	require.NoError(t, err)
	ctx := context.Background()
	_, priv, _ := ed25519.GenerateKey(nil)

	m1 := manifest.New("s")
	m1.Generation = 1
	s1, _ := manifest.Sign(m1, priv)
	require.NoError(t, f.CommitManifest(ctx, s1, 0))

	// Stale expected generation must conflict.
	m2 := manifest.New("s")
	m2.Generation = 2
	s2, _ := manifest.Sign(m2, priv)
	assert.ErrorIs(t, f.CommitManifest(ctx, s2, 0), remote.ErrConflict)

	// Correct expected generation succeeds.
	require.NoError(t, f.CommitManifest(ctx, s2, 1))
}

func TestObjectRoundTrip(t *testing.T) {
	f, err := New(t.TempDir())
	require.NoError(t, err)
	ctx := context.Background()

	id := manifest.ObjectID([]byte("ciphertext"))
	require.NoError(t, f.PutObject(ctx, id, bytes.NewReader([]byte("ciphertext"))))

	present, err := f.HasObjects(ctx, []string{id, "b3:missing"})
	require.NoError(t, err)
	assert.True(t, present[id])
	assert.False(t, present["b3:missing"])

	rc, err := f.GetObject(ctx, id)
	require.NoError(t, err)
	data, _ := io.ReadAll(rc)
	rc.Close()
	assert.Equal(t, "ciphertext", string(data))

	require.NoError(t, f.DeleteObjects(ctx, []string{id}))
	_, err = f.GetObject(ctx, id)
	assert.ErrorIs(t, err, remote.ErrNotFound)
}

func TestCaps(t *testing.T) {
	f, _ := New(t.TempDir())
	caps := f.Caps()
	assert.False(t, caps.AtomicCAS)
	assert.True(t, caps.PartialFetch)
	assert.Equal(t, "fs", f.Name())
}
