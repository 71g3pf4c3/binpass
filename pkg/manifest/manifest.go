// Package manifest defines the binpass vault manifest: the full, signed state
// of a store at a given generation. Objects are content-addressed by the
// BLAKE3 hash of their ciphertext; entries carry version vectors describing
// causality of edits across devices. The manifest is canonicalised to
// deterministic JSON and signed with the store's Ed25519 key to defend
// against rollback and ciphertext substitution.
package manifest

import (
	"encoding/hex"
	"time"

	"lukechampine.com/blake3"
)

// Version is the current manifest schema version.
const Version = 1

// Kind classifies a manifest entry.
type Kind string

// Entry kinds.
const (
	// KindSecret is a normal secret stored as a single object.
	KindSecret Kind = "secret"
	// KindBinary is a chunked binary stored as multiple objects.
	KindBinary Kind = "binary"
	// KindCounter is an auto-incrementing value merged with max() (HOTP).
	KindCounter Kind = "counter"
)

// VersionVector maps a device ID to its per-entry edit counter and captures
// causality between concurrent edits.
type VersionVector map[string]uint64

// ObjectID computes the content address of ciphertext: "b3:" + hex(blake3).
func ObjectID(ciphertext []byte) string {
	sum := blake3.Sum256(ciphertext)
	return "b3:" + hex.EncodeToString(sum[:])
}

// Entry is a single record in the manifest.
type Entry struct {
	// Object is the object ID for single-object secrets.
	Object string `json:"oid,omitempty"`
	// Chunks are the object IDs for chunked binaries.
	Chunks []string `json:"chunks,omitempty"`
	// Size is the plaintext or ciphertext size in bytes.
	Size int64 `json:"size"`
	// Kind classifies the entry.
	Kind Kind `json:"kind"`
	// Version is the entry's version vector.
	Version VersionVector `json:"vv"`
	// Deleted marks a tombstone.
	Deleted bool `json:"deleted,omitempty"`
	// DeletedAt records when the tombstone was created.
	DeletedAt *time.Time `json:"deleted_at,omitempty"`
}

// Manifest is the complete state of a store at a given generation.
type Manifest struct {
	// Version is the schema version.
	Version int `json:"v"`
	// StoreID is the store UUID created at init.
	StoreID string `json:"store_id"`
	// Generation is the monotonic commit counter.
	Generation uint64 `json:"gen"`
	// Entries maps logical path to entry.
	Entries map[string]Entry `json:"entries"`
	// UpdatedAt is the last modification time.
	UpdatedAt time.Time `json:"updated_at"`
}

// New returns an empty manifest for a store.
func New(storeID string) *Manifest {
	return &Manifest{
		Version:    Version,
		StoreID:    storeID,
		Generation: 0,
		Entries:    map[string]Entry{},
		UpdatedAt:  time.Now(),
	}
}

// Clone returns a deep copy of the manifest.
func (m *Manifest) Clone() *Manifest {
	out := &Manifest{
		Version:    m.Version,
		StoreID:    m.StoreID,
		Generation: m.Generation,
		Entries:    make(map[string]Entry, len(m.Entries)),
		UpdatedAt:  m.UpdatedAt,
	}
	for k, e := range m.Entries {
		out.Entries[k] = cloneEntry(e)
	}
	return out
}

// CloneEntry returns a deep copy of an entry.
func CloneEntry(e Entry) Entry { return cloneEntry(e) }

// cloneEntry deep-copies an entry.
func cloneEntry(e Entry) Entry {
	ne := e
	if e.Version != nil {
		ne.Version = make(VersionVector, len(e.Version))
		for k, v := range e.Version {
			ne.Version[k] = v
		}
	}
	if e.Chunks != nil {
		ne.Chunks = append([]string(nil), e.Chunks...)
	}
	if e.DeletedAt != nil {
		t := *e.DeletedAt
		ne.DeletedAt = &t
	}
	return ne
}

// EqualObject reports whether two entries reference the same content
// (object ID and chunk list), ignoring version vectors and timestamps.
func (e Entry) EqualObject(o Entry) bool { return e.equalObject(o) }

// equalObject compares only the content-identifying fields of two entries.
func (e Entry) equalObject(o Entry) bool {
	if e.Object != o.Object || len(e.Chunks) != len(o.Chunks) || e.Deleted != o.Deleted {
		return false
	}
	for i := range e.Chunks {
		if e.Chunks[i] != o.Chunks[i] {
			return false
		}
	}
	return true
}

// ObjectIDs returns all object IDs referenced by non-deleted entries.
func (m *Manifest) ObjectIDs() []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(id string) {
		if id == "" {
			return
		}
		if _, ok := seen[id]; !ok {
			seen[id] = struct{}{}
			out = append(out, id)
		}
	}
	for _, e := range m.Entries {
		if e.Deleted {
			continue
		}
		add(e.Object)
		for _, c := range e.Chunks {
			add(c)
		}
	}
	return out
}
