package blob

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPutGetDelete(t *testing.T) {
	f, err := NewFS(t.TempDir())
	require.NoError(t, err)
	ctx := context.Background()

	n, err := f.Put(ctx, "user1/b3:abc", bytes.NewReader([]byte("ciphertext")))
	require.NoError(t, err)
	assert.Equal(t, int64(10), n)

	rc, err := f.Get(ctx, "user1/b3:abc")
	require.NoError(t, err)
	data, _ := io.ReadAll(rc)
	require.NoError(t, rc.Close())
	assert.Equal(t, "ciphertext", string(data))

	require.NoError(t, f.Delete(ctx, "user1/b3:abc"))
	_, err = f.Get(ctx, "user1/b3:abc")
	assert.Error(t, err)
}

func TestPathTraversalRejected(t *testing.T) {
	f, err := NewFS(t.TempDir())
	require.NoError(t, err)
	_, err = f.Put(context.Background(), "../escape", bytes.NewReader([]byte("x")))
	assert.Error(t, err)
}

func TestDeleteMissingTolerated(t *testing.T) {
	f, err := NewFS(t.TempDir())
	require.NoError(t, err)
	assert.NoError(t, f.Delete(context.Background(), "user1/missing"))
}
