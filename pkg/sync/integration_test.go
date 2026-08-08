package sync

import (
	"bytes"
	"testing"

	"github.com/71g3pf4c3/binpass/pkg/remote"
	"github.com/71g3pf4c3/binpass/pkg/secret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIntegration_TwoClientsOfflineConflict is the M3 acceptance criterion
// from §14: two clients make offline edits to the same entry, sync, detect
// the conflict, and resolve it without losing data.
//
// Flow:
//  1. Both clients start with the same base state.
//  2. Client A edits "alice.gpg" offline (changes password).
//  3. Client B edits "alice.gpg" offline (adds a field).
//  4. Client A syncs: pushes its version to the "remote".
//  5. Client B syncs: detects divergence → conflict.
//  6. Both versions are preserved; no data is lost silently.
func TestIntegration_TwoClientsOfflineConflict(t *testing.T) {
	deviceA := DeviceID("laptop")
	deviceB := DeviceID("phone")

	// Shared base state: alice.gpg with password "oldpass".
	baseVV := VersionVector{"base": 1}
	baseFile := &FileState{
		Path:    "alice.gpg",
		Version: baseVV,
		Hash:    hash(0),
		Size:    10,
		Device:  "base",
	}
	base := Snapshot{"alice.gpg": baseFile}

	// Client A's local state: edited password.
	localA := Snapshot{
		"alice.gpg": &FileState{
			Path:    "alice.gpg",
			Version: baseVV.Increment(deviceA, 1), // {base:1, laptop:1}
			Hash:    hash(1),
			Size:    12,
			Device:  deviceA,
		},
	}

	// Client B's local state: added a field.
	localB := Snapshot{
		"alice.gpg": &FileState{
			Path:    "alice.gpg",
			Version: baseVV.Increment(deviceB, 1), // {base:1, phone:1}
			Hash:    hash(2),
			Size:    15,
			Device:  deviceB,
		},
	}

	// Client A syncs first: its version dominates the base, so push.
	actionsA := Merge(localA, base, base, nil)
	require.Len(t, actionsA, 1)
	assert.Equal(t, ActionPush, actionsA[0].Kind, "client A should push (dominates base)")

	// After client A pushes, the remote now has client A's version.
	remoteAfterA := localA

	// Client B syncs: its version diverges from the remote.
	actionsB := Merge(localB, remoteAfterA, base, nil)
	require.Len(t, actionsB, 1)
	assert.Equal(t, ActionConflict, actionsB[0].Kind, "client B should see a conflict")

	// The conflict action must preserve both sides.
	act := actionsB[0]
	assert.NotNil(t, act.Local, "conflict action must have local state")
	assert.NotNil(t, act.Remote, "conflict action must have remote state")
	assert.Equal(t, "alice.gpg", act.Path)
}

// TestIntegration_HOTPAutoMergeOffline tests that two clients generating HOTP
// codes offline can auto-merge their counters.
func TestIntegration_HOTPAutoMergeOffline(t *testing.T) {
	deviceA := DeviceID("laptop")
	deviceB := DeviceID("phone")

	baseVV := VersionVector{"base": 1}
	base := Snapshot{
		"token.gpg": &FileState{
			Path:    "token.gpg",
			Version: baseVV,
			Hash:    hash(0),
			Device:  "base",
		},
	}

	// Client A advanced the counter to 5.
	localASec := secret.Parse([]byte("hunter2\notpauth://hotp/Service:x?secret=JBSWY3DPEHPK3PXP&counter=5&issuer=Service\n"))
	localA := Snapshot{
		"token.gpg": &FileState{
			Path:    "token.gpg",
			Version: baseVV.Increment(deviceA, 1),
			Hash:    hash(1),
			Device:  deviceA,
		},
	}

	// Client B advanced the counter to 8.
	localBSec := secret.Parse([]byte("hunter2\notpauth://hotp/Service:x?secret=JBSWY3DPEHPK3PXP&counter=8&issuer=Service\n"))
	localB := Snapshot{
		"token.gpg": &FileState{
			Path:    "token.gpg",
			Version: baseVV.Increment(deviceB, 1),
			Hash:    hash(2),
			Device:  deviceB,
		},
	}

	callCount := 0
	opener := OpenerFunc(func(path string) (*secret.Secret, error) {
		callCount++
		if callCount == 1 {
			return localASec, nil
		}
		return localBSec, nil
	})

	// Client B syncs against remote (which has client A's version).
	remoteAfterA := localA
	actions := Merge(localB, remoteAfterA, base, opener)
	require.Len(t, actions, 1)
	assert.Equal(t, ActionMergeHOTP, actions[0].Kind, "HOTP counters should auto-merge")
	assert.Equal(t, uint64(8), actions[0].MergedCounter, "merged counter should be max(5,8)=8")
}

// TestIntegration_NewFileOnBothSides tests that when both clients create a
// file with the same name independently, the conflict is detected after the
// first client pushes its version.
//
// Without a shared base, the merge engine cannot detect the conflict on the
// first sync: it sees a new local file and pushes. The conflict emerges when
// the second client syncs against the remote, which now carries the first
// client's version in the base.
func TestIntegration_NewFileOnBothSides(t *testing.T) {
	deviceA := DeviceID("laptop")
	deviceB := DeviceID("phone")

	// Both clients create "new.gpg" independently, with no prior sync.
	localA := Snapshot{
		"new.gpg": &FileState{
			Path:    "new.gpg",
			Version: VersionVector{deviceA: 1},
			Hash:    hash(1),
			Device:  deviceA,
		},
	}
	localB := Snapshot{
		"new.gpg": &FileState{
			Path:    "new.gpg",
			Version: VersionVector{deviceB: 1},
			Hash:    hash(2),
			Device:  deviceB,
		},
	}

	// Client A syncs first against an empty remote: push (new local file).
	actionsA := Merge(localA, Snapshot{}, nil, nil)
	require.Len(t, actionsA, 1)
	assert.Equal(t, ActionPush, actionsA[0].Kind, "client A should push its new file")

	// After client A's push, the remote has the file. The base for the next
	// sync is client A's version.
	baseAfterA := localA

	// Client B syncs: its version diverges from the remote (now client A's).
	actionsB := Merge(localB, localA, baseAfterA, nil)
	require.Len(t, actionsB, 1)
	assert.Equal(t, ActionConflict, actionsB[0].Kind,
		"client B should see a conflict: both created the same file independently")

	// The conflict preserves both copies.
	act := actionsB[0]
	assert.NotNil(t, act.Local)
	assert.NotNil(t, act.Remote)
}

// TestIntegration_FullSyncCycle simulates a complete sync cycle using a
// MemRemote as the shared transport: initial sync, offline edit, re-sync.
func TestIntegration_FullSyncCycle(t *testing.T) {
	ctx := t.Context()
	rem := remote.NewMemRemote(remote.MemOptions{
		Name: "test",
		Caps: remote.Caps{Atomic: true, History: true, Rename: true},
	})
	defer rem.Close()

	deviceA := DeviceID("laptop")

	// Initial state: remote is empty, local has one file.
	localSnap := Snapshot{
		"alice.gpg": &FileState{
			Path:    "alice.gpg",
			Version: VersionVector{deviceA: 1},
			Hash:    hash(1),
			Size:    10,
			Device:  deviceA,
		},
	}

	// Step 1: First sync. Remote is empty, so all local files are new.
	remoteFiles, err := rem.List(ctx)
	require.NoError(t, err)
	remoteSnap := remoteFilesToSnapshot(remoteFiles, nil, deviceA)
	actions := Merge(localSnap, remoteSnap, nil, nil)
	require.Len(t, actions, 1)
	assert.Equal(t, ActionPush, actions[0].Kind)

	// Simulate pushing: write to remote.
	_, err = rem.Put(ctx, "alice.gpg", bytes.NewReader([]byte("encrypted")), "")
	require.NoError(t, err)

	// Step 2: Re-sync. Now remote has the file with matching VV.
	remoteFiles, err = rem.List(ctx)
	require.NoError(t, err)
	remoteSnap = remoteFilesToSnapshot(remoteFiles, localSnap, deviceA)

	actions = Merge(localSnap, remoteSnap, localSnap, nil)
	require.Len(t, actions, 1)
	assert.Equal(t, ActionNone, actions[0].Kind, "unchanged file should be a no-op")
}

// remoteFilesToSnapshot converts a list of RemoteFile into a Snapshot.
// This mirrors the CLI helper and is duplicated here to avoid importing
// the CLI package from tests.
func remoteFilesToSnapshot(files []remote.RemoteFile, base Snapshot, deviceID DeviceID) Snapshot {
	snap := make(Snapshot, len(files))
	for _, f := range files {
		vv := VersionVector{}
		if b, ok := base[f.Path]; ok {
			vv = b.Version.Clone()
		} else {
			vv = VersionVector{deviceID: 1}
		}
		snap[f.Path] = &FileState{
			Path:      f.Path,
			Size:      f.Size,
			ModTime:   f.ModTime,
			Version:   vv,
			RemoteRev: f.Rev,
			Device:    deviceID,
		}
	}
	return snap
}
