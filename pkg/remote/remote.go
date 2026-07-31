// Package remote defines the synchronisation transport contract used by the
// binpass sync engine. Every backend — the binpass server, git, and rclone —
// implements the same Remote interface, so a single sync engine drives them
// all. Capabilities a backend lacks are advertised via Caps, and the engine
// degrades accordingly (e.g. polling when Watch is unsupported).
package remote

import (
	"context"
	"errors"
	"io"

	"github.com/71g3pf4c3/binpass/pkg/manifest"
)

//go:generate mockgen -source=remote.go -destination=mocks/remote_mock.go -package=mocks

// ErrConflict is returned by CommitManifest when the compare-and-swap fails
// because the remote advanced concurrently.
var ErrConflict = errors.New("remote: manifest generation conflict")

// ErrNotFound is returned when a manifest or object does not exist.
var ErrNotFound = errors.New("remote: not found")

// Caps advertises which optional features a backend supports.
type Caps struct {
	// AtomicCAS is true when the backend offers true compare-and-swap.
	AtomicCAS bool
	// History is true when the backend retains past manifests.
	History bool
	// Watch is true when the backend can stream change notifications.
	Watch bool
	// PartialFetch is true when objects can be fetched individually.
	PartialFetch bool
}

// Remote is the synchronisation transport.
type Remote interface {
	// Name returns a short backend identifier for logs and config.
	Name() string
	// Caps reports the backend's capabilities.
	Caps() Caps

	// Manifest returns the current signed manifest, or ErrNotFound.
	Manifest(ctx context.Context) (*manifest.Signed, error)
	// CommitManifest commits m if the remote generation equals expect,
	// otherwise returns ErrConflict.
	CommitManifest(ctx context.Context, m *manifest.Signed, expect uint64) error

	// HasObjects reports which of ids already exist on the remote.
	HasObjects(ctx context.Context, ids []string) (map[string]bool, error)
	// PutObject stores object id, reading ciphertext from r.
	PutObject(ctx context.Context, id string, r io.Reader) error
	// GetObject opens object id for reading, or returns ErrNotFound.
	GetObject(ctx context.Context, id string) (io.ReadCloser, error)
	// DeleteObjects removes the given objects (best-effort GC).
	DeleteObjects(ctx context.Context, ids []string) error

	// Close releases transport resources.
	Close() error
}
