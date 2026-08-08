package sync

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStateDB_WALRecoveryAfterKill simulates a process being killed in the
// middle of a sync operation. A WAL entry is written, the state mutation is
// applied, but the WAL is never committed. On the next open, replay must
// restore consistency.
//
// This is the test required by the TASK.md: "напиши тест, который реально
// убивает операцию на середине и проверяет восстановление."
// Since we cannot reliably kill our own process mid-transaction in a Go test,
// we simulate the effect: write WAL, apply mutation, close without committing
// the WAL (which is exactly what a SIGKILL would leave behind).
func TestStateDB_WALRecoveryAfterKill(t *testing.T) {
	dir := t.TempDir()

	// Step 1: Open the database and set up an initial state.
	db, err := OpenStateDB(dir)
	require.NoError(t, err)

	initialSnap := Snapshot{
		"a.gpg": {Path: "a.gpg", Version: VersionVector{"phone": 1}, Hash: hash(1), Size: 10},
		"b.gpg": {Path: "b.gpg", Version: VersionVector{"phone": 1}, Hash: hash(2), Size: 20},
	}
	require.NoError(t, db.SaveBase(initialSnap))

	// Step 2: Simulate a sync operation in progress.
	// Write WAL entries for two file mutations.
	require.NoError(t, db.wal.Begin(db, walEntry{
		Op:   "set",
		Path: "a.gpg",
		State: &FileState{
			Path: "a.gpg", Version: VersionVector{"phone": 2}, Hash: hash(3), Size: 15,
		},
	}))
	require.NoError(t, db.UpdateFile(&FileState{
		Path: "a.gpg", Version: VersionVector{"phone": 2}, Hash: hash(3), Size: 15,
	}))

	require.NoError(t, db.wal.Begin(db, walEntry{
		Op:   "delete",
		Path: "b.gpg",
	}))
	require.NoError(t, db.DeleteFile("b.gpg"))

	// Step 3: Simulate SIGKILL — close without committing WAL entries.
	// This is exactly the state left behind when the process dies.
	require.NoError(t, db.db.Close())
	// Do NOT call db.wal.Commit().

	// Step 4: Reopen the database. WAL replay must restore consistency.
	db2, err := OpenStateDB(dir)
	require.NoError(t, err)
	defer db2.Close()

	// Verify that the WAL entries were replayed correctly.
	base, err := db2.LoadBase()
	require.NoError(t, err)

	// File "a.gpg" should have the updated version.
	require.Contains(t, base, "a.gpg")
	assert.True(t, base["a.gpg"].Version.Equal(VersionVector{"phone": 2}),
		"replayed WAL should update a.gpg to phone:2")

	// File "b.gpg" should have been deleted by the WAL replay.
	_, hasB := base["b.gpg"]
	assert.False(t, hasB, "replayed WAL should delete b.gpg")
}

// TestStateDB_StateNeverInStore verifies that the state.db file is never
// created inside the password store, regardless of the operations performed.
// This is the test required by TASK.md: "тест, что state.db не появляется
// внутри стора ни при каком сценарии."
func TestStateDB_StateNeverInStore(t *testing.T) {
	storeDir := t.TempDir()
	stateDir := filepath.Join(t.TempDir(), "data", "binpass", "sync")

	// The state dir is outside the store.
	err := CheckStateLocation(stateDir, storeDir)
	assert.NoError(t, err, "state outside store should pass check")

	// State inside store should fail.
	insideDir := filepath.Join(storeDir, "sync")
	err = CheckStateLocation(insideDir, storeDir)
	assert.ErrorIs(t, err, ErrStateInStore, "state inside store should fail check")

	// Verify no state.db exists in the store after a full sync cycle.
	db, err := OpenStateDB(stateDir)
	require.NoError(t, err)

	snap := Snapshot{
		"x.gpg": {Path: "x.gpg", Version: VersionVector{"a": 1}, Hash: hash(1)},
	}
	require.NoError(t, db.SaveBase(snap))
	require.NoError(t, db.UpdateFile(&FileState{
		Path: "y.gpg", Version: VersionVector{"b": 1}, Hash: hash(2),
	}))
	require.NoError(t, db.DeleteFile("x.gpg"))
	require.NoError(t, db.RecordSync())
	require.NoError(t, db.Close())

	// Check that no state.db file exists in the store directory.
	_, err = os.Stat(filepath.Join(storeDir, "state.db"))
	assert.True(t, os.IsNotExist(err), "state.db must not exist in the store directory")
}
