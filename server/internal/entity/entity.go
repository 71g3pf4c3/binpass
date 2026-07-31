// Package entity holds the core domain types of binpassd. These types have
// zero external dependencies and know nothing about transport or storage.
package entity

import (
	"errors"
	"time"
)

// Domain errors returned by use cases and mapped to transport codes by the
// controller layer.
var (
	// ErrLoginTaken is returned when a registration login already exists.
	ErrLoginTaken = errors.New("login already taken")
	// ErrInvalidCredentials is returned on failed authentication.
	ErrInvalidCredentials = errors.New("invalid credentials")
	// ErrNotFound is returned when a requested resource does not exist.
	ErrNotFound = errors.New("not found")
	// ErrGenerationMismatch is returned when a manifest CAS commit loses the
	// race against a concurrent commit.
	ErrGenerationMismatch = errors.New("manifest generation mismatch")
	// ErrTokenInvalid is returned for expired, unknown, or reused tokens.
	ErrTokenInvalid = errors.New("token invalid")
	// ErrPermissionDenied is returned when a caller accesses another owner's
	// resource.
	ErrPermissionDenied = errors.New("permission denied")
	// ErrQuotaExceeded is returned when a user exceeds their storage quota.
	ErrQuotaExceeded = errors.New("quota exceeded")
	// ErrObjectTooLarge is returned when an object exceeds the size limit.
	ErrObjectTooLarge = errors.New("object too large")
)

// User is a registered account. The server stores only the Argon2id hash of
// the client-derived auth secret, never a password or encryption key.
type User struct {
	// ID is the unique user identifier.
	ID string
	// Login is the unique account name.
	Login string
	// AuthHash is the Argon2id hash of the client auth secret.
	AuthHash string
	// UserSalt is the per-user salt for client key derivation.
	UserSalt []byte
	// CreatedAt is the account creation time.
	CreatedAt time.Time
}

// Device is an enrolled client belonging to a user.
type Device struct {
	// ID is the unique device identifier.
	ID string
	// UserID is the owning user.
	UserID string
	// Name is a human label.
	Name string
	// CreatedAt is when the device was enrolled.
	CreatedAt time.Time
	// LastSeenAt is the last authenticated activity time.
	LastSeenAt time.Time
	// RevokedAt is set when the device is revoked.
	RevokedAt *time.Time
}

// Revoked reports whether the device has been revoked.
func (d Device) Revoked() bool { return d.RevokedAt != nil }

// RefreshToken is a stored, hashed refresh token bound to a device. Tokens
// rotate on every use; reuse of a rotated token revokes the chain.
type RefreshToken struct {
	// ID is the token identifier.
	ID string
	// DeviceID is the bound device.
	DeviceID string
	// UserID is the owning user.
	UserID string
	// TokenHash is the SHA-256 hash of the opaque token.
	TokenHash string
	// ExpiresAt is the token expiry.
	ExpiresAt time.Time
	// UsedAt is set once the token has been rotated.
	UsedAt *time.Time
	// Revoked marks the token (and its chain) as revoked.
	Revoked bool
}

// Manifest is a signed, end-to-end-encrypted vault manifest committed by a
// device. The server treats Blob and Signature as opaque bytes.
type Manifest struct {
	// UserID is the owning user.
	UserID string
	// Generation is the monotonic commit counter.
	Generation uint64
	// Blob is the canonical JSON manifest ciphertext-metadata (opaque).
	Blob []byte
	// Signature is the Ed25519 signature over the manifest.
	Signature []byte
	// PublicKey is the store signing public key.
	PublicKey []byte
	// DeviceID is the committing device.
	DeviceID string
	// CreatedAt is the commit time.
	CreatedAt time.Time
}

// Object is a content-addressed ciphertext blob referenced by manifests.
type Object struct {
	// UserID is the owning user.
	UserID string
	// OID is the content-addressed identifier (e.g. "b3:<hex>").
	OID string
	// Size is the ciphertext byte length.
	Size int64
	// StorageRef locates the blob in the blob store.
	StorageRef string
	// CreatedAt is when the object was first stored.
	CreatedAt time.Time
}

// ChangeEvent notifies a subscribed device that the vault advanced.
type ChangeEvent struct {
	// Generation is the new manifest generation.
	Generation uint64
	// DeviceID is the device that produced the change.
	DeviceID string
	// At is when the change was committed.
	At time.Time
}

// Session is the authenticated context extracted from an access token.
type Session struct {
	// UserID is the authenticated user.
	UserID string
	// DeviceID is the authenticated device.
	DeviceID string
}
