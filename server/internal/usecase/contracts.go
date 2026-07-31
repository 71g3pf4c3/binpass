// Package usecase implements binpassd business logic. It depends only on the
// entity layer and the interfaces declared here; it knows nothing about gRPC,
// HTTP, or PostgreSQL. Interfaces are declared by the consumer (this package)
// so that repositories and infrastructure can be swapped and mocked freely.
package usecase

import (
	"context"
	"io"
	"time"

	"github.com/71g3pf4c3/binpass/server/internal/entity"
)

// UserRepo persists users.
type UserRepo interface {
	// Create inserts a new user, returning entity.ErrLoginTaken on conflict.
	Create(ctx context.Context, u entity.User) error
	// ByLogin returns the user with the given login, or entity.ErrNotFound.
	ByLogin(ctx context.Context, login string) (entity.User, error)
	// ByID returns the user with the given ID, or entity.ErrNotFound.
	ByID(ctx context.Context, id string) (entity.User, error)
}

// DeviceRepo persists devices.
type DeviceRepo interface {
	// Create inserts a new device.
	Create(ctx context.Context, d entity.Device) error
	// ByID returns a device by ID, or entity.ErrNotFound.
	ByID(ctx context.Context, id string) (entity.Device, error)
	// ListByUser returns all devices of a user.
	ListByUser(ctx context.Context, userID string) ([]entity.Device, error)
	// Revoke marks a device revoked at the given time.
	Revoke(ctx context.Context, userID, deviceID string, at time.Time) error
	// Touch updates a device's last-seen timestamp.
	Touch(ctx context.Context, deviceID string, at time.Time) error
}

// TokenRepo persists hashed refresh tokens.
type TokenRepo interface {
	// Create stores a new refresh token.
	Create(ctx context.Context, t entity.RefreshToken) error
	// ByHash returns a token by its hash, or entity.ErrNotFound.
	ByHash(ctx context.Context, hash string) (entity.RefreshToken, error)
	// MarkUsed records that a token was rotated at the given time.
	MarkUsed(ctx context.Context, id string, at time.Time) error
	// Revoke revokes a single token.
	Revoke(ctx context.Context, id string) error
	// RevokeByDevice revokes all tokens of a device (chain compromise).
	RevokeByDevice(ctx context.Context, deviceID string) error
}

// ManifestRepo persists signed manifests with compare-and-swap semantics.
type ManifestRepo interface {
	// Latest returns the newest manifest for a user, or entity.ErrNotFound.
	Latest(ctx context.Context, userID string) (entity.Manifest, error)
	// InsertIfNext inserts a manifest only if its generation is exactly one
	// greater than the current latest; otherwise returns
	// entity.ErrGenerationMismatch.
	InsertIfNext(ctx context.Context, m entity.Manifest, expectGeneration uint64) error
}

// ObjectRepo persists object metadata (not the ciphertext itself).
type ObjectRepo interface {
	// Exists reports which of the given OIDs exist for a user.
	Exists(ctx context.Context, userID string, oids []string) (map[string]bool, error)
	// Upsert records object metadata.
	Upsert(ctx context.Context, o entity.Object) error
	// Get returns object metadata, or entity.ErrNotFound.
	Get(ctx context.Context, userID, oid string) (entity.Object, error)
}

// BlobStore stores and retrieves opaque ciphertext blobs.
type BlobStore interface {
	// Put stores the blob under ref, reading from r.
	Put(ctx context.Context, ref string, r io.Reader) (size int64, err error)
	// Get opens the blob at ref for reading.
	Get(ctx context.Context, ref string) (io.ReadCloser, error)
	// Delete removes the blob at ref.
	Delete(ctx context.Context, ref string) error
}

// TokenIssuer issues signed access tokens.
type TokenIssuer interface {
	// Issue signs an access token for the user and device.
	Issue(userID, deviceID string) (token string, expiresAt time.Time, err error)
}

// Hasher hashes and verifies auth secrets.
type Hasher interface {
	// Hash returns an encoded hash of secret.
	Hash(secret string) (string, error)
}

// EventBus fans out vault change events to subscribed devices.
type EventBus interface {
	// Publish announces a new generation for a user.
	Publish(userID string, ev entity.ChangeEvent)
	// Subscribe returns a channel of change events for a user; cancel unsubs.
	Subscribe(ctx context.Context, userID string) <-chan entity.ChangeEvent
}
