package usecase

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/71g3pf4c3/binpass/server/internal/entity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newVaultUC builds a VaultUseCase backed by in-memory fakes.
func newVaultUC(maxObj int64) *VaultUseCase {
	return NewVault(newFakeManifestRepo(), newFakeObjectRepo(), newFakeBlobStore(), noopBus{}, maxObj)
}

func TestManifestEmptyNotFound(t *testing.T) {
	uc := newVaultUC(0)
	_, err := uc.GetManifest(context.Background(), "user1")
	assert.ErrorIs(t, err, entity.ErrNotFound)
}

func TestCommitAndGetManifest(t *testing.T) {
	uc := newVaultUC(0)
	ctx := context.Background()

	gen, err := uc.CommitManifest(ctx, "user1", "dev1", entity.Manifest{Blob: []byte("m1")}, 0)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), gen)

	m, err := uc.GetManifest(ctx, "user1")
	require.NoError(t, err)
	assert.Equal(t, []byte("m1"), m.Blob)
	assert.Equal(t, uint64(1), m.Generation)
}

func TestCommitCASConflict(t *testing.T) {
	uc := newVaultUC(0)
	ctx := context.Background()
	_, err := uc.CommitManifest(ctx, "user1", "dev1", entity.Manifest{Blob: []byte("m1")}, 0)
	require.NoError(t, err)

	// Stale expected generation loses the CAS race.
	_, err = uc.CommitManifest(ctx, "user1", "dev1", entity.Manifest{Blob: []byte("m2")}, 0)
	assert.ErrorIs(t, err, entity.ErrGenerationMismatch)

	// Correct expected generation succeeds.
	gen, err := uc.CommitManifest(ctx, "user1", "dev1", entity.Manifest{Blob: []byte("m2")}, 1)
	require.NoError(t, err)
	assert.Equal(t, uint64(2), gen)
}

func TestObjectRoundTrip(t *testing.T) {
	uc := newVaultUC(0)
	ctx := context.Background()

	obj, err := uc.PutObject(ctx, "user1", "b3:abc", 10, bytes.NewReader([]byte("ciphertext!")))
	require.NoError(t, err)
	assert.Equal(t, int64(11), obj.Size)

	present, err := uc.HasObjects(ctx, "user1", []string{"b3:abc", "b3:none"})
	require.NoError(t, err)
	assert.True(t, present["b3:abc"])
	assert.False(t, present["b3:none"])

	rc, err := uc.GetObject(ctx, "user1", "b3:abc")
	require.NoError(t, err)
	data, _ := io.ReadAll(rc)
	require.NoError(t, rc.Close())
	assert.Equal(t, "ciphertext!", string(data))
}

func TestObjectOwnerIsolation(t *testing.T) {
	uc := newVaultUC(0)
	ctx := context.Background()
	_, err := uc.PutObject(ctx, "user1", "b3:abc", 3, bytes.NewReader([]byte("xxx")))
	require.NoError(t, err)

	_, err = uc.GetObject(ctx, "user2", "b3:abc")
	assert.ErrorIs(t, err, entity.ErrNotFound)
}

func TestObjectTooLarge(t *testing.T) {
	uc := newVaultUC(5)
	_, err := uc.PutObject(context.Background(), "user1", "b3:big", 100, bytes.NewReader([]byte("way too big")))
	assert.ErrorIs(t, err, entity.ErrObjectTooLarge)
}
