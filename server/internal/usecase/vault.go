package usecase

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/71g3pf4c3/binpass/server/internal/entity"
)

// VaultUseCase implements manifest compare-and-swap, object storage, and
// change-event fan-out. It handles only ciphertext and opaque metadata.
type VaultUseCase struct {
	// manifests, objects are persistence ports.
	manifests ManifestRepo
	objects   ObjectRepo
	// blobs stores object ciphertext.
	blobs BlobStore
	// events fans out change notifications.
	events EventBus
	// maxObjectSize bounds a single object's byte length.
	maxObjectSize int64
}

// NewVault builds a VaultUseCase.
func NewVault(manifests ManifestRepo, objects ObjectRepo, blobs BlobStore, events EventBus, maxObjectSize int64) *VaultUseCase {
	return &VaultUseCase{
		manifests:     manifests,
		objects:       objects,
		blobs:         blobs,
		events:        events,
		maxObjectSize: maxObjectSize,
	}
}

// GetManifest returns the latest manifest for a user, or entity.ErrNotFound
// if the vault is empty.
func (uc *VaultUseCase) GetManifest(ctx context.Context, userID string) (entity.Manifest, error) {
	return uc.manifests.Latest(ctx, userID)
}

// CommitManifest atomically commits a new manifest via compare-and-swap on
// expectGeneration, then publishes a change event.
func (uc *VaultUseCase) CommitManifest(ctx context.Context, userID, deviceID string, m entity.Manifest, expectGeneration uint64) (uint64, error) {
	m.UserID = userID
	m.DeviceID = deviceID
	m.Generation = expectGeneration + 1
	m.CreatedAt = time.Now()

	if err := uc.manifests.InsertIfNext(ctx, m, expectGeneration); err != nil {
		return 0, err
	}
	uc.events.Publish(userID, entity.ChangeEvent{
		Generation: m.Generation,
		DeviceID:   deviceID,
		At:         m.CreatedAt,
	})
	return m.Generation, nil
}

// HasObjects reports which of the given OIDs already exist for the user.
func (uc *VaultUseCase) HasObjects(ctx context.Context, userID string, oids []string) (map[string]bool, error) {
	return uc.objects.Exists(ctx, userID, oids)
}

// PutObject streams a ciphertext object to the blob store and records its
// metadata. It rejects objects larger than the configured limit.
func (uc *VaultUseCase) PutObject(ctx context.Context, userID, oid string, totalSize int64, r io.Reader) (entity.Object, error) {
	if uc.maxObjectSize > 0 && totalSize > uc.maxObjectSize {
		return entity.Object{}, entity.ErrObjectTooLarge
	}
	ref := userID + "/" + oid
	limited := r
	if uc.maxObjectSize > 0 {
		limited = io.LimitReader(r, uc.maxObjectSize+1)
	}
	size, err := uc.blobs.Put(ctx, ref, limited)
	if err != nil {
		return entity.Object{}, fmt.Errorf("vault: put blob: %w", err)
	}
	if uc.maxObjectSize > 0 && size > uc.maxObjectSize {
		_ = uc.blobs.Delete(ctx, ref)
		return entity.Object{}, entity.ErrObjectTooLarge
	}
	obj := entity.Object{
		UserID:     userID,
		OID:        oid,
		Size:       size,
		StorageRef: ref,
		CreatedAt:  time.Now(),
	}
	if err := uc.objects.Upsert(ctx, obj); err != nil {
		return entity.Object{}, err
	}
	return obj, nil
}

// GetObject opens a ciphertext object for reading, verifying ownership.
func (uc *VaultUseCase) GetObject(ctx context.Context, userID, oid string) (io.ReadCloser, error) {
	obj, err := uc.objects.Get(ctx, userID, oid)
	if err != nil {
		return nil, err
	}
	rc, err := uc.blobs.Get(ctx, obj.StorageRef)
	if err != nil {
		return nil, fmt.Errorf("vault: get blob: %w", err)
	}
	return rc, nil
}

// Watch subscribes to change events for a user until ctx is cancelled.
func (uc *VaultUseCase) Watch(ctx context.Context, userID string, sinceGeneration uint64) (<-chan entity.ChangeEvent, error) {
	if uc.events == nil {
		return nil, errors.New("vault: events disabled")
	}
	return uc.events.Subscribe(ctx, userID), nil
}
