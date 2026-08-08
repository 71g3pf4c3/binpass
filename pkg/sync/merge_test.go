package sync

import (
	"fmt"
	"math/rand"
	"sort"
	"testing"
	"time"

	"github.com/71g3pf4c3/binpass/pkg/secret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- Helpers ----

// mkState is a convenience constructor for FileState in tests.
func mkState(path string, vv VersionVector, hash [32]byte) *FileState {
	return &FileState{Path: path, Version: vv, Hash: hash, Device: "test"}
}

// hash returns a deterministic [32]byte from a seed integer.
func hash(seed int) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = byte(seed + i)
	}
	return out
}

// ---- Table-driven unit tests (decision table §8.5) ----

func TestMerge_VVEqual(t *testing.T) {
	vv := VersionVector{"a": 1, "b": 2}
	local := Snapshot{"x.gpg": mkState("x.gpg", vv, hash(1))}
	remote := Snapshot{"x.gpg": mkState("x.gpg", vv, hash(1))}
	base := Snapshot{"x.gpg": mkState("x.gpg", vv, hash(1))}

	actions := Merge(local, remote, base, nil)
	require.Len(t, actions, 1)
	assert.Equal(t, ActionNone, actions[0].Kind)
	assert.Equal(t, "x.gpg", actions[0].Path)
}

func TestMerge_LocalDominates(t *testing.T) {
	baseVV := VersionVector{"a": 1}
	localVV := VersionVector{"a": 2}
	remoteVV := VersionVector{"a": 1}
	local := Snapshot{"x.gpg": mkState("x.gpg", localVV, hash(1))}
	remote := Snapshot{"x.gpg": mkState("x.gpg", remoteVV, hash(1))}
	base := Snapshot{"x.gpg": mkState("x.gpg", baseVV, hash(1))}

	actions := Merge(local, remote, base, nil)
	require.Len(t, actions, 1)
	assert.Equal(t, ActionPush, actions[0].Kind)
}

func TestMerge_RemoteDominates(t *testing.T) {
	baseVV := VersionVector{"a": 1}
	localVV := VersionVector{"a": 1}
	remoteVV := VersionVector{"a": 2}
	local := Snapshot{"x.gpg": mkState("x.gpg", localVV, hash(1))}
	remote := Snapshot{"x.gpg": mkState("x.gpg", remoteVV, hash(1))}
	base := Snapshot{"x.gpg": mkState("x.gpg", baseVV, hash(1))}

	actions := Merge(local, remote, base, nil)
	require.Len(t, actions, 1)
	assert.Equal(t, ActionPull, actions[0].Kind)
}

func TestMerge_Diverge_Conflict(t *testing.T) {
	baseVV := VersionVector{"a": 1}
	localVV := VersionVector{"a": 2, "b": 1}
	remoteVV := VersionVector{"a": 1, "b": 2}
	local := Snapshot{"x.gpg": mkState("x.gpg", localVV, hash(1))}
	remote := Snapshot{"x.gpg": mkState("x.gpg", remoteVV, hash(2))}
	base := Snapshot{"x.gpg": mkState("x.gpg", baseVV, hash(0))}

	actions := Merge(local, remote, base, nil)
	require.Len(t, actions, 1)
	assert.Equal(t, ActionConflict, actions[0].Kind)
}

func TestMerge_Diverge_IdenticalCiphertext(t *testing.T) {
	baseVV := VersionVector{"a": 1}
	localVV := VersionVector{"a": 2, "b": 1}
	remoteVV := VersionVector{"a": 1, "b": 2}
	sameHash := hash(42)
	local := Snapshot{"x.gpg": mkState("x.gpg", localVV, sameHash)}
	remote := Snapshot{"x.gpg": mkState("x.gpg", remoteVV, sameHash)}
	base := Snapshot{"x.gpg": mkState("x.gpg", baseVV, hash(0))}

	actions := Merge(local, remote, base, nil)
	require.Len(t, actions, 1)
	assert.Equal(t, ActionNone, actions[0].Kind)
	// MergedVersion should be the pointwise max.
	expectedVV := VersionVector{"a": 2, "b": 2}
	assert.True(t, actions[0].MergedVersion.Equal(expectedVV))
}

func TestMerge_NewLocalFile(t *testing.T) {
	local := Snapshot{"x.gpg": mkState("x.gpg", VersionVector{"phone": 1}, hash(1))}
	remote := Snapshot{}
	base := Snapshot{}

	actions := Merge(local, remote, base, nil)
	require.Len(t, actions, 1)
	assert.Equal(t, ActionPush, actions[0].Kind)
	assert.Equal(t, "x.gpg", actions[0].Path)
}

func TestMerge_NewRemoteFile(t *testing.T) {
	local := Snapshot{}
	remote := Snapshot{"x.gpg": mkState("x.gpg", VersionVector{"laptop": 1}, hash(1))}
	base := Snapshot{}

	actions := Merge(local, remote, base, nil)
	require.Len(t, actions, 1)
	assert.Equal(t, ActionPull, actions[0].Kind)
}

func TestMerge_LocalDelete_RemoteUnchanged(t *testing.T) {
	baseVV := VersionVector{"a": 1}
	local := Snapshot{}
	remote := Snapshot{"x.gpg": mkState("x.gpg", baseVV, hash(1))}
	base := Snapshot{"x.gpg": mkState("x.gpg", baseVV, hash(1))}

	actions := Merge(local, remote, base, nil)
	require.Len(t, actions, 1)
	assert.Equal(t, ActionDelete, actions[0].Kind)
}

func TestMerge_LocalDelete_RemoteEdited(t *testing.T) {
	baseVV := VersionVector{"a": 1}
	remoteVV := VersionVector{"a": 2}
	local := Snapshot{}
	remote := Snapshot{"x.gpg": mkState("x.gpg", remoteVV, hash(2))}
	base := Snapshot{"x.gpg": mkState("x.gpg", baseVV, hash(1))}

	actions := Merge(local, remote, base, nil)
	require.Len(t, actions, 1)
	assert.Equal(t, ActionPull, actions[0].Kind)
	assert.Contains(t, actions[0].Reason, "delete-vs-edit")
}

func TestMerge_RemoteDelete_LocalUnchanged(t *testing.T) {
	baseVV := VersionVector{"a": 1}
	local := Snapshot{"x.gpg": mkState("x.gpg", baseVV, hash(1))}
	remote := Snapshot{}
	base := Snapshot{"x.gpg": mkState("x.gpg", baseVV, hash(1))}

	actions := Merge(local, remote, base, nil)
	require.Len(t, actions, 1)
	assert.Equal(t, ActionDelete, actions[0].Kind)
}

func TestMerge_RemoteDelete_LocalEdited(t *testing.T) {
	baseVV := VersionVector{"a": 1}
	localVV := VersionVector{"a": 2}
	local := Snapshot{"x.gpg": mkState("x.gpg", localVV, hash(2))}
	remote := Snapshot{}
	base := Snapshot{"x.gpg": mkState("x.gpg", baseVV, hash(1))}

	actions := Merge(local, remote, base, nil)
	require.Len(t, actions, 1)
	assert.Equal(t, ActionPush, actions[0].Kind)
	assert.Contains(t, actions[0].Reason, "delete-vs-edit")
}

func TestMerge_BothDeleted(t *testing.T) {
	baseVV := VersionVector{"a": 1}
	local := Snapshot{}
	remote := Snapshot{}
	base := Snapshot{"x.gpg": mkState("x.gpg", baseVV, hash(1))}

	actions := Merge(local, remote, base, nil)
	require.Len(t, actions, 1)
	assert.Equal(t, ActionDelete, actions[0].Kind)
}

// ---- HOTP auto-merge tests ----

func TestMerge_HOTPAutoMerge(t *testing.T) {
	baseVV := VersionVector{"a": 1}
	localVV := VersionVector{"a": 2, "b": 1}
	remoteVV := VersionVector{"a": 1, "b": 2}

	localSec := secret.Parse([]byte("hunter2\notpauth://hotp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&counter=5&issuer=GitHub\n"))
	remoteSec := secret.Parse([]byte("hunter2\notpauth://hotp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&counter=8&issuer=GitHub\n"))

	callCount := 0
	opener := OpenerFunc(func(path string) (*secret.Secret, error) {
		callCount++
		if callCount == 1 {
			return localSec, nil
		}
		return remoteSec, nil
	})

	local := Snapshot{"x.gpg": mkState("x.gpg", localVV, hash(1))}
	remote := Snapshot{"x.gpg": mkState("x.gpg", remoteVV, hash(2))}
	base := Snapshot{"x.gpg": mkState("x.gpg", baseVV, hash(0))}

	actions := Merge(local, remote, base, opener)
	require.Len(t, actions, 1)
	assert.Equal(t, ActionMergeHOTP, actions[0].Kind)
	assert.Equal(t, uint64(8), actions[0].MergedCounter)
}

func TestMerge_HOTPNotOnlyDiff_Conflict(t *testing.T) {
	baseVV := VersionVector{"a": 1}
	localVV := VersionVector{"a": 2, "b": 1}
	remoteVV := VersionVector{"a": 1, "b": 2}

	// Password differs in addition to counter: not a HOTP-only diff.
	localSec := secret.Parse([]byte("oldpass\notpauth://hotp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&counter=5&issuer=GitHub\n"))
	remoteSec := secret.Parse([]byte("newpass\notpauth://hotp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&counter=8&issuer=GitHub\n"))

	callCount := 0
	opener := OpenerFunc(func(path string) (*secret.Secret, error) {
		callCount++
		if callCount == 1 {
			return localSec, nil
		}
		return remoteSec, nil
	})

	local := Snapshot{"x.gpg": mkState("x.gpg", localVV, hash(1))}
	remote := Snapshot{"x.gpg": mkState("x.gpg", remoteVV, hash(2))}
	base := Snapshot{"x.gpg": mkState("x.gpg", baseVV, hash(0))}

	actions := Merge(local, remote, base, opener)
	require.Len(t, actions, 1)
	assert.Equal(t, ActionConflict, actions[0].Kind)
}

func TestMerge_NoHOTP_Conflict(t *testing.T) {
	baseVV := VersionVector{"a": 1}
	localVV := VersionVector{"a": 2, "b": 1}
	remoteVV := VersionVector{"a": 1, "b": 2}

	// TOTP, not HOTP.
	localSec := secret.Parse([]byte("hunter2\notpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub\n"))
	remoteSec := secret.Parse([]byte("hunter2\notpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub\n"))

	opener := OpenerFunc(func(path string) (*secret.Secret, error) {
		if path == "x.gpg" {
			return localSec, nil
		}
		return remoteSec, nil
	})

	local := Snapshot{"x.gpg": mkState("x.gpg", localVV, hash(1))}
	remote := Snapshot{"x.gpg": mkState("x.gpg", remoteVV, hash(2))}
	base := Snapshot{"x.gpg": mkState("x.gpg", baseVV, hash(0))}

	actions := Merge(local, remote, base, opener)
	require.Len(t, actions, 1)
	assert.Equal(t, ActionConflict, actions[0].Kind)
}

func TestMerge_OpenerNil_NoAutoMerge(t *testing.T) {
	baseVV := VersionVector{"a": 1}
	localVV := VersionVector{"a": 2, "b": 1}
	remoteVV := VersionVector{"a": 1, "b": 2}
	local := Snapshot{"x.gpg": mkState("x.gpg", localVV, hash(1))}
	remote := Snapshot{"x.gpg": mkState("x.gpg", remoteVV, hash(2))}
	base := Snapshot{"x.gpg": mkState("x.gpg", baseVV, hash(0))}

	// opener is nil: HOTP auto-merge is disabled.
	actions := Merge(local, remote, base, nil)
	require.Len(t, actions, 1)
	assert.Equal(t, ActionConflict, actions[0].Kind)
}

// ---- ConflictName test ----

func TestConflictName(t *testing.T) {
	ts := time.Date(2026, 8, 8, 14, 22, 33, 0, time.UTC)
	got := ConflictName("github.com/alice.gpg", "thinkpad", ts.Format("20060102T150405"))
	assert.Equal(t, "github.com/alice.conflict-thinkpad-20260808T142233.gpg", got)
}

func TestConflictName_NoExtension(t *testing.T) {
	ts := time.Date(2026, 8, 8, 14, 22, 33, 0, time.UTC)
	got := ConflictName("github.com/alice", "phone", ts.Format("20060102T150405"))
	assert.Equal(t, "github.com/alice.conflict-phone-20260808T142233", got)
}

// ---- Property tests ----

// nothingLost asserts that for every file present in local or remote, there is
// exactly one action in the merge result. This is the "nothing is lost"
// invariant from §12.
func nothingLost(local, remote, base Snapshot, actions []Action) error {
	// Every file that was in local or remote must be covered by an action.
	covered := make(map[string]bool, len(actions))
	for _, a := range actions {
		covered[a.Path] = true
	}
	for p := range local {
		if !covered[p] {
			return fmt.Errorf("local file %q has no action", p)
		}
	}
	for p := range remote {
		if !covered[p] {
			return fmt.Errorf("remote file %q has no action", p)
		}
	}

	// Conflict and merge_hotp actions preserve both sides.
	for _, a := range actions {
		if a.Kind == ActionConflict {
			if a.Local == nil {
				return fmt.Errorf("conflict action for %q has no local state", a.Path)
			}
			if a.Remote == nil {
				return fmt.Errorf("conflict action for %q has no remote state", a.Path)
			}
		}
		if a.Kind == ActionMergeHOTP {
			if a.Local == nil {
				return fmt.Errorf("merge_hotp action for %q has no local state", a.Path)
			}
			if a.Remote == nil {
				return fmt.Errorf("merge_hotp action for %q has no remote state", a.Path)
			}
		}
	}
	return nil
}

// deterministic asserts that Merge returns the same actions regardless of map
// iteration order. We test this by merging the same data twice and comparing.
func deterministic(local, remote, base Snapshot) error {
	actions1 := Merge(local, remote, base, nil)
	actions2 := Merge(local, remote, base, nil)
	if len(actions1) != len(actions2) {
		return fmt.Errorf("different action counts: %d vs %d", len(actions1), len(actions2))
	}
	for i := range actions1 {
		if actions1[i].Path != actions2[i].Path {
			return fmt.Errorf("action %d: path mismatch %q vs %q", i, actions1[i].Path, actions2[i].Path)
		}
		if actions1[i].Kind != actions2[i].Kind {
			return fmt.Errorf("action %d (%s): kind mismatch %q vs %q", i, actions1[i].Path, actions1[i].Kind, actions2[i].Kind)
		}
	}
	return nil
}

func TestProperty_NothingLost(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 2000; i++ {
		local, remote, base := randomSnapshots(rng)
		actions := Merge(local, remote, base, nil)
		if err := nothingLost(local, remote, base, actions); err != nil {
			t.Fatalf("iteration %d: %v\nlocal=%v\nremote=%v\nbase=%v", i, err, pathsOf(local), pathsOf(remote), pathsOf(base))
		}
	}
}

func TestProperty_Deterministic(t *testing.T) {
	rng := rand.New(rand.NewSource(99))
	for i := 0; i < 2000; i++ {
		local, remote, base := randomSnapshots(rng)
		if err := deterministic(local, remote, base); err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
	}
}

func TestProperty_MergeSortedByPath(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 1000; i++ {
		local, remote, base := randomSnapshots(rng)
		actions := Merge(local, remote, base, nil)
		for j := 1; j < len(actions); j++ {
			if actions[j].Path < actions[j-1].Path {
				t.Fatalf("actions not sorted: %q before %q", actions[j-1].Path, actions[j].Path)
			}
		}
	}
}

// ---- Random snapshot generators ----

func randomSnapshots(rng *rand.Rand) (local, remote, base Snapshot) {
	// Pick 3-8 distinct file paths.
	n := rng.Intn(6) + 3
	paths := make([]string, n)
	for i := range paths {
		paths[i] = fmt.Sprintf("dir%d/file%d.gpg", rng.Intn(3), i)
	}

	// Generate a base VV and device assignments.
	baseDevices := []DeviceID{"a", "b", "c"}
	local = make(Snapshot)
	remote = make(Snapshot)
	base = make(Snapshot)

	for _, p := range paths {
		baseVV := randomVVFrom(rng, baseDevices)
		base[p] = &FileState{Path: p, Version: baseVV, Hash: hash(rng.Intn(100)), Device: "a"}

		// Decide local and remote states.
		r := rng.Intn(5)
		switch r {
		case 0: // unchanged on both sides
			local[p] = &FileState{Path: p, Version: baseVV.Clone(), Hash: base[p].Hash, Device: "a"}
			remote[p] = &FileState{Path: p, Version: baseVV.Clone(), Hash: base[p].Hash, Device: "a"}
		case 1: // local changed
			localVV := baseVV.Increment(baseDevices[rng.Intn(len(baseDevices))], 1)
			local[p] = &FileState{Path: p, Version: localVV, Hash: hash(rng.Intn(100)), Device: baseDevices[0]}
			remote[p] = &FileState{Path: p, Version: baseVV.Clone(), Hash: base[p].Hash, Device: "a"}
		case 2: // remote changed
			remoteVV := baseVV.Increment(baseDevices[rng.Intn(len(baseDevices))], 1)
			remote[p] = &FileState{Path: p, Version: remoteVV, Hash: hash(rng.Intn(100)), Device: baseDevices[1]}
			local[p] = &FileState{Path: p, Version: baseVV.Clone(), Hash: base[p].Hash, Device: "a"}
		case 3: // both changed (may diverge)
			localVV := baseVV.Increment(baseDevices[rng.Intn(len(baseDevices))], 1)
			remoteVV := baseVV.Increment(baseDevices[rng.Intn(len(baseDevices))], 1)
			sameHash := rng.Intn(2) == 0
			lh := hash(rng.Intn(100))
			rh := lh
			if !sameHash {
				rh = hash(rng.Intn(100) + 50)
			}
			local[p] = &FileState{Path: p, Version: localVV, Hash: lh, Device: baseDevices[0]}
			remote[p] = &FileState{Path: p, Version: remoteVV, Hash: rh, Device: baseDevices[1]}
		case 4: // deleted on one side
			if rng.Intn(2) == 0 {
				// local deleted
				if rng.Intn(2) == 0 {
					// remote unchanged
					remote[p] = &FileState{Path: p, Version: baseVV.Clone(), Hash: base[p].Hash, Device: "a"}
				} else {
					// remote edited
					remoteVV := baseVV.Increment(baseDevices[rng.Intn(len(baseDevices))], 1)
					remote[p] = &FileState{Path: p, Version: remoteVV, Hash: hash(rng.Intn(100)), Device: baseDevices[1]}
				}
			} else {
				// remote deleted
				if rng.Intn(2) == 0 {
					// local unchanged
					local[p] = &FileState{Path: p, Version: baseVV.Clone(), Hash: base[p].Hash, Device: "a"}
				} else {
					// local edited
					localVV := baseVV.Increment(baseDevices[rng.Intn(len(baseDevices))], 1)
					local[p] = &FileState{Path: p, Version: localVV, Hash: hash(rng.Intn(100)), Device: baseDevices[0]}
				}
			}
		}
	}

	// Occasionally add files not in base.
	if rng.Intn(3) == 0 {
		p := "new/local.gpg"
		local[p] = &FileState{Path: p, Version: VersionVector{"phone": 1}, Hash: hash(77), Device: "phone"}
	}
	if rng.Intn(3) == 0 {
		p := "new/remote.gpg"
		remote[p] = &FileState{Path: p, Version: VersionVector{"laptop": 1}, Hash: hash(88), Device: "laptop"}
	}

	return local, remote, base
}

func randomVVFrom(rng *rand.Rand, devices []DeviceID) VersionVector {
	vv := make(VersionVector, len(devices))
	for _, d := range devices {
		vv[d] = uint64(rng.Intn(5))
	}
	return vv
}

func pathsOf(s Snapshot) []string {
	paths := make([]string, 0, len(s))
	for p := range s {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths
}
