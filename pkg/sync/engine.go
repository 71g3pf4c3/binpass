package sync

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/71g3pf4c3/binpass/pkg/manifest"
	"github.com/71g3pf4c3/binpass/pkg/remote"
)

//go:generate mockgen -source=engine.go -destination=mocks/engine_mock.go -package=mocks

// maxCommitRetries bounds CAS retry attempts on a busy remote.
const maxCommitRetries = 8

// Local is the sync engine's view of the local working tree. The store
// implements it; tests mock it. The engine treats ciphertext as opaque.
type Local interface {
	// StoreID returns the store's stable UUID.
	StoreID() string
	// DeviceID returns this device's stable identifier.
	DeviceID() string
	// SigningKey returns the store's Ed25519 manifest-signing key.
	SigningKey() (ed25519.PrivateKey, error)
	// BuildManifest constructs the current manifest from the working tree and
	// the base manifest (for version-vector continuity).
	BuildManifest(base *manifest.Manifest) (*manifest.Manifest, error)
	// ReadObject returns the ciphertext bytes for an object ID.
	ReadObject(id string) ([]byte, error)
	// WriteObject stores ciphertext for object id into the tree, mapping it to
	// the given logical path.
	WriteObject(path, id string, ciphertext []byte) error
	// ApplyDeletion removes the entry at path from the working tree.
	ApplyDeletion(path string) error
	// WriteConflictCopy stores the local losing side of a conflict under a
	// sibling path derived from path and returns that path.
	WriteConflictCopy(path string, ciphertext []byte) (string, error)
	// HasEntry reports whether a working-tree file exists at path.
	HasEntry(path string) bool
	// EntryObject returns the object ID of the working-tree file at path, or
	// "" if it does not exist.
	EntryObject(path string) string
}

// State persists the sync anchor: the base manifest (common ancestor).
type State interface {
	// LoadBase returns the last merged manifest, or nil if none.
	LoadBase() (*manifest.Manifest, error)
	// SaveBase stores the merged manifest as the new base.
	SaveBase(m *manifest.Manifest) error
}

// Engine drives synchronisation between the local tree and a Remote.
type Engine struct {
	// local is the working-tree adapter.
	local Local
	// state persists the base manifest.
	state State
}

// NewEngine builds a sync Engine.
func NewEngine(local Local, state State) *Engine {
	return &Engine{local: local, state: state}
}

// Report summarises the outcome of a Sync.
type Report struct {
	// Pushed is the number of objects uploaded.
	Pushed int
	// Pulled is the number of objects downloaded.
	Pulled int
	// Generation is the committed manifest generation.
	Generation uint64
	// Conflicts lists conflicts materialised during the merge.
	Conflicts []Conflict
}

// Sync performs one synchronisation cycle against r: build the local manifest,
// three-way merge with the remote, push new objects, commit under CAS (with
// retry), then pull new objects and persist the new base. Nothing is ever
// lost: concurrent edits become sibling conflict copies.
func (e *Engine) Sync(ctx context.Context, r remote.Remote) (*Report, error) {
	signKey, err := e.local.SigningKey()
	if err != nil {
		return nil, err
	}
	pubKey := signKey.Public().(ed25519.PublicKey)

	base, err := e.state.LoadBase()
	if err != nil {
		return nil, err
	}
	if base == nil {
		base = manifest.New(e.local.StoreID())
	}

	report := &Report{}
	for attempt := 0; attempt < maxCommitRetries; attempt++ {
		remoteM, remoteGen, err := e.fetchRemoteManifest(ctx, r, pubKey, base.Generation)
		if err != nil {
			return nil, err
		}
		localM, err := e.local.BuildManifest(base)
		if err != nil {
			return nil, err
		}

		result := Merge3(base, localM, remoteM)
		merged := result.Merged

		// Materialise conflict copies (local losing side) as sibling entries
		// and add them directly to the merged manifest. We must NOT re-merge
		// here: re-merging would re-decide the canonical path and could flip
		// the winner back to the freshly-rebuilt local side.
		if err := e.materialiseConflicts(merged, result.Conflicts); err != nil {
			return nil, err
		}

		merged.Generation = remoteGen + 1
		merged.StoreID = e.local.StoreID()

		pushed, err := e.pushObjects(ctx, r, merged)
		if err != nil {
			return nil, err
		}
		report.Pushed += pushed

		signed, err := manifest.Sign(merged, signKey)
		if err != nil {
			return nil, err
		}
		if err := r.CommitManifest(ctx, signed, remoteGen); err != nil {
			if errors.Is(err, remote.ErrConflict) {
				time.Sleep(backoff(attempt))
				continue
			}
			return nil, fmt.Errorf("sync: commit: %w", err)
		}

		pulled, err := e.pullObjects(ctx, r, base, merged)
		if err != nil {
			return nil, err
		}
		report.Pulled += pulled

		if err := e.state.SaveBase(merged); err != nil {
			return nil, err
		}
		report.Generation = merged.Generation
		report.Conflicts = result.Conflicts
		return report, nil
	}
	return nil, fmt.Errorf("sync: commit retries exhausted: %w", remote.ErrConflict)
}

// fetchRemoteManifest returns the remote manifest (empty if none) and its
// generation, verifying the signature and rollback protection.
func (e *Engine) fetchRemoteManifest(ctx context.Context, r remote.Remote, pub ed25519.PublicKey, minGen uint64) (*manifest.Manifest, uint64, error) {
	signed, err := r.Manifest(ctx)
	if errors.Is(err, remote.ErrNotFound) {
		return manifest.New(e.local.StoreID()), 0, nil
	}
	if err != nil {
		return nil, 0, fmt.Errorf("sync: fetch manifest: %w", err)
	}
	m, err := manifest.Verify(signed, nil, minGen)
	if err != nil {
		return nil, 0, err
	}
	return m, m.Generation, nil
}

// pushObjects uploads every object referenced by merged that the remote lacks.
func (e *Engine) pushObjects(ctx context.Context, r remote.Remote, merged *manifest.Manifest) (int, error) {
	ids := merged.ObjectIDs()
	if len(ids) == 0 {
		return 0, nil
	}
	present, err := r.HasObjects(ctx, ids)
	if err != nil {
		return 0, fmt.Errorf("sync: has objects: %w", err)
	}
	pushed := 0
	for _, id := range ids {
		if present[id] {
			continue
		}
		data, err := e.local.ReadObject(id)
		if err != nil {
			return pushed, fmt.Errorf("sync: read object %s: %w", id, err)
		}
		if err := r.PutObject(ctx, id, bytesReader(data)); err != nil {
			return pushed, fmt.Errorf("sync: put object %s: %w", id, err)
		}
		pushed++
	}
	return pushed, nil
}

// pullObjects downloads objects for entries new or changed relative to base
// and writes them into the working tree.
func (e *Engine) pullObjects(ctx context.Context, r remote.Remote, base, merged *manifest.Manifest) (int, error) {
	pulled := 0
	for _, path := range merged.SortedPaths() {
		entry := merged.Entries[path]
		if entry.Deleted {
			if _, existed := base.Entries[path]; existed {
				if err := e.local.ApplyDeletion(path); err != nil {
					return pulled, err
				}
			}
			continue
		}
		if entry.Object == "" {
			continue // chunked binaries handled elsewhere
		}
		prev, had := base.Entries[path]
		// Skip only when the entry is unchanged AND the working-tree file is
		// already present; otherwise (e.g. a freshly materialised sibling or a
		// missing local file) we must write it out.
		if had && prev.EqualObject(entry) && e.local.HasEntry(path) {
			continue
		}
		if e.local.HasEntry(path) && e.local.EntryObject(path) == entry.Object {
			continue // already present with the right content
		}
		rc, err := r.GetObject(ctx, entry.Object)
		if err != nil {
			return pulled, fmt.Errorf("sync: get object %s: %w", entry.Object, err)
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return pulled, fmt.Errorf("sync: read pulled object: %w", err)
		}
		if err := e.local.WriteObject(path, entry.Object, data); err != nil {
			return pulled, err
		}
		pulled++
	}
	return pulled, nil
}

// materialiseConflicts writes the local losing side of each conflict as a
// sibling copy so no data is silently lost, and records each sibling as a new
// entry in the merged manifest (without re-deciding any canonical path).
func (e *Engine) materialiseConflicts(merged *manifest.Manifest, conflicts []Conflict) error {
	for _, c := range conflicts {
		if c.Local.Object == "" {
			continue
		}
		data, err := e.local.ReadObject(c.Local.Object)
		if err != nil {
			// The local object may already be gone; skip rather than fail.
			continue
		}
		sibling, err := e.local.WriteConflictCopy(c.Path, data)
		if err != nil {
			return err
		}
		merged.Entries[sibling] = manifest.Entry{
			Object:  c.Local.Object,
			Size:    c.Local.Size,
			Kind:    manifest.KindSecret,
			Version: manifest.Bump(nil, e.local.DeviceID()),
		}
	}
	return nil
}

// backoff returns an increasing delay for CAS retries.
func backoff(attempt int) time.Duration {
	return time.Duration(1<<attempt) * 10 * time.Millisecond
}
