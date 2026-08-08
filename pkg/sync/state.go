package sync

import (
	"time"

	"github.com/71g3pf4c3/binpass/pkg/secret"
)

// FileState describes what binpass knows about a single file at the moment of
// the last successful synchronisation (§8.1). It is the unit of comparison
// between the local store, the remote transport, and the base state held in
// state.db.
//
// # Change detection order
//
// The primary change detector is (Size, ModTime): if both match the stored
// state, the file is considered unchanged and the hash is not recomputed.
// This matters because GPG encryption is non-deterministic: re-encrypting the
// same plaintext yields different ciphertext and thus a different hash. A
// stale (Size, ModTime) check would miss a real edit, so the metadata check
// must come first.
//
// # Hash scope
//
// Hash is blake3 of the ciphertext, not the plaintext. This allows the sync
// engine to operate on a locked store (no decryption key required) while still
// detecting identical files across devices.
type FileState struct {
	// Path is the store-relative path of the file, for example
	// "github.com/alice.gpg".
	Path string
	// Hash is the blake3 digest of the ciphertext. It is used to confirm
	// changes detected by (Size, ModTime) and to detect identical files
	// across devices without decryption.
	Hash [32]byte
	// Size is the file size in bytes.
	Size int64
	// ModTime is the file modification time.
	ModTime time.Time
	// Version tracks the causal history of this file across devices.
	Version VersionVector
	// RemoteRev is the transport-specific revision identifier: a git SHA,
	// an S3 ETag, a Drive revision, and so on. It is opaque to the merge
	// engine but is stored in state.db for the transport layer.
	RemoteRev string
	// Device is the device that last modified this file. It is used for
	// conflict file naming (e.g. alice.conflict-thinkpad-20260808T142233.gpg).
	Device DeviceID
}

// Snapshot is a complete view of a store at a point in time, mapping each
// store-relative path to its file state. A missing entry means the file does
// not exist in that snapshot.
type Snapshot map[string]*FileState

// Opener decrypts a file from the store. It is used exclusively for the HOTP
// counter auto-merge special case (§8.5), the only place the sync engine reads
// plaintext. A nil Opener means HOTP auto-merge is disabled and divergent
// HOTP counters will be treated as regular conflicts.
type Opener interface {
	// Open decrypts the file at the store-relative path and returns its
	// plaintext content.
	Open(path string) (*secret.Secret, error)
}

// OpenerFunc is a convenience adapter for the Opener interface.
type OpenerFunc func(path string) (*secret.Secret, error)

// Open calls f(path).
func (f OpenerFunc) Open(path string) (*secret.Secret, error) {
	return f(path)
}
