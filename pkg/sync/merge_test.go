package sync

import (
	"testing"

	"github.com/71g3pf4c3/binpass/pkg/manifest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mk builds a manifest with the given entries for tests.
func mk(entries map[string]manifest.Entry) *manifest.Manifest {
	m := manifest.New("s")
	for k, v := range entries {
		m.Entries[k] = v
	}
	return m
}

func TestMergeLocalOnlyNew(t *testing.T) {
	base := mk(nil)
	local := mk(map[string]manifest.Entry{"a": {Object: "b3:1", Version: manifest.VersionVector{"L": 1}}})
	remote := mk(nil)
	res := Merge3(base, local, remote)
	assert.Contains(t, res.Merged.Entries, "a")
	assert.Empty(t, res.Conflicts)
}

func TestMergeRemoteOnlyNew(t *testing.T) {
	base := mk(nil)
	local := mk(nil)
	remote := mk(map[string]manifest.Entry{"a": {Object: "b3:1", Version: manifest.VersionVector{"R": 1}}})
	res := Merge3(base, local, remote)
	assert.Contains(t, res.Merged.Entries, "a")
	assert.Empty(t, res.Conflicts)
}

func TestMergeRemoteWinsWhenNewer(t *testing.T) {
	base := mk(map[string]manifest.Entry{"a": {Object: "b3:1", Version: manifest.VersionVector{"L": 1}}})
	local := mk(map[string]manifest.Entry{"a": {Object: "b3:1", Version: manifest.VersionVector{"L": 1}}})
	remote := mk(map[string]manifest.Entry{"a": {Object: "b3:2", Version: manifest.VersionVector{"L": 1, "R": 1}}})
	res := Merge3(base, local, remote)
	assert.Equal(t, "b3:2", res.Merged.Entries["a"].Object)
	assert.Empty(t, res.Conflicts)
}

func TestMergeLocalWinsWhenNewer(t *testing.T) {
	base := mk(map[string]manifest.Entry{"a": {Object: "b3:1", Version: manifest.VersionVector{"R": 1}}})
	local := mk(map[string]manifest.Entry{"a": {Object: "b3:9", Version: manifest.VersionVector{"R": 1, "L": 1}}})
	remote := mk(map[string]manifest.Entry{"a": {Object: "b3:1", Version: manifest.VersionVector{"R": 1}}})
	res := Merge3(base, local, remote)
	assert.Equal(t, "b3:9", res.Merged.Entries["a"].Object)
	assert.Empty(t, res.Conflicts)
}

func TestMergeConcurrentEditConflict(t *testing.T) {
	base := mk(map[string]manifest.Entry{"a": {Object: "b3:0", Version: manifest.VersionVector{}}})
	local := mk(map[string]manifest.Entry{"a": {Object: "b3:L", Version: manifest.VersionVector{"L": 1}}})
	remote := mk(map[string]manifest.Entry{"a": {Object: "b3:R", Version: manifest.VersionVector{"R": 1}}})
	res := Merge3(base, local, remote)
	require.Len(t, res.Conflicts, 1)
	assert.Equal(t, ConflictConcurrentEdit, res.Conflicts[0].Kind)
	// Remote wins the canonical path.
	assert.Equal(t, "b3:R", res.Merged.Entries["a"].Object)
}

func TestMergeDeleteVsEdit(t *testing.T) {
	base := mk(map[string]manifest.Entry{"a": {Object: "b3:0", Version: manifest.VersionVector{}}})
	local := mk(map[string]manifest.Entry{"a": {Deleted: true, Version: manifest.VersionVector{"L": 1}}})
	remote := mk(map[string]manifest.Entry{"a": {Object: "b3:R", Version: manifest.VersionVector{"R": 1}}})
	res := Merge3(base, local, remote)
	require.Len(t, res.Conflicts, 1)
	assert.Equal(t, ConflictDeleteEdit, res.Conflicts[0].Kind)
	// Edit wins: entry is not deleted.
	assert.False(t, res.Merged.Entries["a"].Deleted)
	assert.Equal(t, "b3:R", res.Merged.Entries["a"].Object)
}

func TestMergeCounterMax(t *testing.T) {
	base := mk(nil)
	local := mk(map[string]manifest.Entry{"c": {Size: 5, Kind: manifest.KindCounter, Version: manifest.VersionVector{"L": 1}}})
	remote := mk(map[string]manifest.Entry{"c": {Size: 9, Kind: manifest.KindCounter, Version: manifest.VersionVector{"R": 1}}})
	res := Merge3(base, local, remote)
	assert.Empty(t, res.Conflicts)
	assert.Equal(t, int64(9), res.Merged.Entries["c"].Size)
}

func TestMergeRemoteDeletionAccepted(t *testing.T) {
	base := mk(map[string]manifest.Entry{"a": {Object: "b3:1", Version: manifest.VersionVector{"L": 1}}})
	local := mk(map[string]manifest.Entry{"a": {Object: "b3:1", Version: manifest.VersionVector{"L": 1}}})
	remote := mk(nil) // remote removed it
	res := Merge3(base, local, remote)
	assert.NotContains(t, res.Merged.Entries, "a")
}

// FuzzMerge3NoDataLoss asserts the core invariant: every path present in
// local or remote survives the merge in some form (kept, replaced, or
// tombstoned) — nothing vanishes silently — and merging is deterministic.
func FuzzMerge3NoDataLoss(f *testing.F) {
	f.Add(uint64(1), uint64(1), uint64(0), true, true)
	f.Fuzz(func(t *testing.T, lv, rv, bv uint64, hasLocal, hasRemote bool) {
		base := mk(map[string]manifest.Entry{"a": {Object: "b3:base", Version: manifest.VersionVector{"B": bv}}})
		local := mk(nil)
		remote := mk(nil)
		if hasLocal {
			local.Entries["a"] = manifest.Entry{Object: "b3:L", Version: manifest.VersionVector{"L": lv}}
		}
		if hasRemote {
			remote.Entries["a"] = manifest.Entry{Object: "b3:R", Version: manifest.VersionVector{"R": rv}}
		}

		res := Merge3(base, local, remote)
		// Determinism: merging again yields the same entry set.
		res2 := Merge3(base, local.Clone(), remote.Clone())
		assert.Equal(t, len(res.Merged.Entries), len(res2.Merged.Entries))

		// If either side had the entry live, it must be represented (present or
		// tombstoned) in the merged manifest.
		if hasLocal || hasRemote {
			_, ok := res.Merged.Entries["a"]
			assert.True(t, ok, "entry a must survive merge")
		}
	})
}
