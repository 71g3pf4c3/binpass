// Package remote defines the client-side synchronisation transport contract
// and its gRPC implementation against binpassd. It is the client counterpart
// to the server's Vault/Auth services and lives with the server module so it
// shares the generated protobuf types.
package remote

import (
	"context"
	"errors"
	"io"
)

// ErrConflict is returned when a manifest commit loses the CAS race.
var ErrConflict = errors.New("remote: manifest generation conflict")

// SignedManifest is the client view of a signed vault manifest.
type SignedManifest struct {
	// Manifest is the canonical JSON manifest bytes.
	Manifest []byte
	// Signature is the Ed25519 signature over the manifest.
	Signature []byte
	// PublicKey is the store signing public key.
	PublicKey []byte
	// Generation is the monotonic commit counter.
	Generation uint64
}

// Remote is the synchronisation transport. The server, git, and rclone
// backends all implement it identically so a single sync engine drives them.
type Remote interface {
	// Manifest returns the current signed manifest.
	Manifest(ctx context.Context) (*SignedManifest, error)
	// CommitManifest commits m under compare-and-swap on expect; a mismatch
	// returns ErrConflict.
	CommitManifest(ctx context.Context, m *SignedManifest, expect uint64) (uint64, error)
	// HasObjects reports which object IDs already exist on the remote.
	HasObjects(ctx context.Context, ids []string) (map[string]bool, error)
	// PutObject uploads a ciphertext object read from r.
	PutObject(ctx context.Context, oid string, size int64, r io.Reader) error
	// GetObject downloads a ciphertext object.
	GetObject(ctx context.Context, oid string) (io.ReadCloser, error)
	// Close releases transport resources.
	Close() error
}
