// Package sync implements the binpass synchronisation engine: a three-way
// merge of manifests driven by version vectors, deterministic conflict
// resolution, a write-ahead log for crash safety, and the push/commit/pull
// loop that any Remote backend can drive.
package sync

import (
	"time"

	"github.com/71g3pf4c3/binpass/pkg/manifest"
)

// ConflictKind classifies why an entry could not be merged automatically.
type ConflictKind string

// Conflict kinds.
const (
	// ConflictConcurrentEdit is a genuine concurrent edit of the same entry.
	ConflictConcurrentEdit ConflictKind = "concurrent-edit"
	// ConflictDeleteEdit is a delete on one side and an edit on the other.
	ConflictDeleteEdit ConflictKind = "delete-edit"
)

// Conflict records a merge conflict for user reporting.
type Conflict struct {
	// Path is the logical entry path.
	Path string
	// Kind classifies the conflict.
	Kind ConflictKind
	// Local is the local entry at conflict time.
	Local manifest.Entry
	// Remote is the remote entry at conflict time.
	Remote manifest.Entry
}

// MergeResult is the outcome of a three-way merge.
type MergeResult struct {
	// Merged is the resulting manifest (generation not yet assigned).
	Merged *manifest.Manifest
	// Conflicts lists entries requiring user attention.
	Conflicts []Conflict
}

// Merge3 performs a three-way merge of local and remoteM against their common
// ancestor base. It never loses data: concurrent edits become conflicts that
// the caller materialises as sibling entries. Counter entries (HOTP) merge as
// max(). The merge is deterministic regardless of argument order for the
// non-conflicting cases.
func Merge3(base, local, remoteM *manifest.Manifest) MergeResult {
	merged := local.Clone()
	if merged.Entries == nil {
		merged.Entries = map[string]manifest.Entry{}
	}
	var conflicts []Conflict

	paths := unionPaths(base, local, remoteM)
	for _, path := range paths {
		b, hasB := entryOf(base, path)
		l, hasL := entryOf(local, path)
		r, hasR := entryOf(remoteM, path)

		switch {
		case !hasL && !hasR:
			// Present only in base (already gone both sides): drop.
			delete(merged.Entries, path)

		case hasL && !hasR:
			// Only local knows it. Keep unless remote deleted a shared entry.
			if hasB && b.EqualObject(l) {
				// Remote removed it and local didn't touch it: accept removal.
				delete(merged.Entries, path)
			}

		case !hasL && hasR:
			// Only remote knows it (or local removed a shared entry).
			if hasB && b.EqualObject(r) {
				// Local removed it and remote didn't touch it: keep removed.
				delete(merged.Entries, path)
			} else {
				merged.Entries[path] = manifest.CloneEntry(r)
			}

		default:
			// Present on both sides.
			resolved, conflict := mergeEntry(path, l, r)
			merged.Entries[path] = resolved
			if conflict != nil {
				conflicts = append(conflicts, *conflict)
			}
		}
	}

	merged.UpdatedAt = time.Now()
	return MergeResult{Merged: merged, Conflicts: conflicts}
}

// mergeEntry merges two present entries by version-vector causality.
func mergeEntry(path string, l, r manifest.Entry) (manifest.Entry, *Conflict) {
	// Counter entries always merge deterministically as max().
	if l.Kind == manifest.KindCounter || r.Kind == manifest.KindCounter {
		return mergeCounter(l, r), nil
	}

	switch manifest.Compare(l.Version, r.Version) {
	case manifest.Equal, manifest.Dominates:
		// Local is newer or identical: keep local, absorb remote causality.
		out := manifest.CloneEntry(l)
		out.Version = manifest.MergeVV(l.Version, r.Version)
		return out, nil
	case manifest.DominatedBy:
		// Remote is newer: take remote.
		out := manifest.CloneEntry(r)
		out.Version = manifest.MergeVV(l.Version, r.Version)
		return out, nil
	default:
		// Concurrent divergence.
		if l.Deleted != r.Deleted {
			// delete vs edit: edit wins, tombstone lifted, user warned.
			winner := l
			if l.Deleted {
				winner = r
			}
			out := manifest.CloneEntry(winner)
			out.Deleted = false
			out.DeletedAt = nil
			out.Version = manifest.MergeVV(l.Version, r.Version)
			return out, &Conflict{Path: path, Kind: ConflictDeleteEdit, Local: l, Remote: r}
		}
		// Concurrent edit: remote wins the canonical path; caller keeps local
		// as a sibling. Merge causality so the decision sticks.
		out := manifest.CloneEntry(r)
		out.Version = manifest.MergeVV(l.Version, r.Version)
		return out, &Conflict{Path: path, Kind: ConflictConcurrentEdit, Local: l, Remote: r}
	}
}

// mergeCounter merges two counter entries as the pointwise max of value and
// version vector. The larger object (higher counter) wins.
func mergeCounter(l, r manifest.Entry) manifest.Entry {
	out := manifest.CloneEntry(l)
	if r.Size > l.Size {
		out = manifest.CloneEntry(r)
	}
	out.Kind = manifest.KindCounter
	out.Version = manifest.MergeVV(l.Version, r.Version)
	return out
}

// unionPaths returns the sorted union of entry paths across the manifests.
func unionPaths(ms ...*manifest.Manifest) []string {
	seen := map[string]struct{}{}
	for _, m := range ms {
		if m == nil {
			continue
		}
		for p := range m.Entries {
			seen[p] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sortStrings(out)
	return out
}

// entryOf returns the entry at path and whether it exists.
func entryOf(m *manifest.Manifest, path string) (manifest.Entry, bool) {
	if m == nil {
		return manifest.Entry{}, false
	}
	e, ok := m.Entries[path]
	return e, ok
}
