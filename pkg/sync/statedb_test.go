package sync

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStateDB_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenStateDB(dir)
	require.NoError(t, err)
	defer db.Close()

	// Empty base.
	base, err := db.LoadBase()
	require.NoError(t, err)
	assert.Empty(t, base)

	// Save a snapshot.
	snap := Snapshot{
		"a/b.gpg": {Path: "a/b.gpg", Version: VersionVector{"phone": 2}, Hash: hash(1), Size: 42},
		"c.gpg":   {Path: "c.gpg", Version: VersionVector{"laptop": 1}, Hash: hash(2), Size: 99},
	}
	require.NoError(t, db.SaveBase(snap))

	// Load and verify.
	loaded, err := db.LoadBase()
	require.NoError(t, err)
	require.Len(t, loaded, 2)
	assert.True(t, loaded["a/b.gpg"].Version.Equal(VersionVector{"phone": 2}))
	assert.Equal(t, int64(42), loaded["a/b.gpg"].Size)
	assert.True(t, loaded["c.gpg"].Version.Equal(VersionVector{"laptop": 1}))

	// Save again (replaces).
	snap2 := Snapshot{
		"a/b.gpg": {Path: "a/b.gpg", Version: VersionVector{"phone": 3}, Hash: hash(3), Size: 50},
	}
	require.NoError(t, db.SaveBase(snap2))

	loaded2, err := db.LoadBase()
	require.NoError(t, err)
	require.Len(t, loaded2, 1)
	assert.True(t, loaded2["a/b.gpg"].Version.Equal(VersionVector{"phone": 3}))
}

func TestStateDB_UpdateDeleteFile(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenStateDB(dir)
	require.NoError(t, err)
	defer db.Close()

	// Save initial state.
	snap := Snapshot{
		"x.gpg": {Path: "x.gpg", Version: VersionVector{"a": 1}, Hash: hash(1)},
	}
	require.NoError(t, db.SaveBase(snap))

	// Update a single file.
	require.NoError(t, db.UpdateFile(&FileState{
		Path: "x.gpg", Version: VersionVector{"a": 2}, Hash: hash(2), Size: 10,
	}))

	base, err := db.LoadBase()
	require.NoError(t, err)
	assert.True(t, base["x.gpg"].Version.Equal(VersionVector{"a": 2}))

	// Add a new file via UpdateFile.
	require.NoError(t, db.UpdateFile(&FileState{
		Path: "y.gpg", Version: VersionVector{"b": 1}, Hash: hash(3), Size: 5,
	}))

	base, err = db.LoadBase()
	require.NoError(t, err)
	require.Len(t, base, 2)

	// Delete a file.
	require.NoError(t, db.DeleteFile("x.gpg"))

	base, err = db.LoadBase()
	require.NoError(t, err)
	require.Len(t, base, 1)
	_, ok := base["y.gpg"]
	assert.True(t, ok)
}

func TestStateDB_DeviceID(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenStateDB(dir)
	require.NoError(t, err)
	defer db.Close()

	id, err := db.DeviceID()
	require.NoError(t, err)
	assert.Empty(t, id)

	require.NoError(t, db.SetDeviceID("thinkpad"))

	id, err = db.DeviceID()
	require.NoError(t, err)
	assert.Equal(t, DeviceID("thinkpad"), id)
}

func TestStateDB_LastSync(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenStateDB(dir)
	require.NoError(t, err)
	defer db.Close()

	ts, err := db.LastSync()
	require.NoError(t, err)
	assert.True(t, ts.IsZero())

	require.NoError(t, db.RecordSync())

	ts, err = db.LastSync()
	require.NoError(t, err)
	assert.False(t, ts.IsZero())
	assert.WithinDuration(t, time.Now().UTC(), ts, 2*time.Second)
}

func TestStateDB_WALReplay(t *testing.T) {
	dir := t.TempDir()

	// Open, write state, write WAL entry, close without committing.
	db, err := OpenStateDB(dir)
	require.NoError(t, err)

	snap := Snapshot{
		"x.gpg": {Path: "x.gpg", Version: VersionVector{"a": 1}, Hash: hash(1)},
	}
	require.NoError(t, db.SaveBase(snap))

	// Simulate a partial operation: write WAL, apply mutation, but don't
	// commit the WAL. In a real crash, the process would die here.
	require.NoError(t, db.wal.Begin(db, walEntry{
		Op:    "set",
		Path:  "y.gpg",
		State: &FileState{Path: "y.gpg", Version: VersionVector{"b": 1}, Hash: hash(2)},
	}))
	require.NoError(t, db.UpdateFile(&FileState{
		Path: "y.gpg", Version: VersionVector{"b": 1}, Hash: hash(2),
	}))
	require.NoError(t, db.Close())

	// Reopen: WAL replay should apply the pending entry.
	db2, err := OpenStateDB(dir)
	require.NoError(t, err)
	defer db2.Close()

	base, err := db2.LoadBase()
	require.NoError(t, err)
	_, ok := base["y.gpg"]
	assert.True(t, ok, "WAL replay should restore y.gpg")
}

func TestStateDB_StateNotInStore(t *testing.T) {
	// Verify that CheckStateLocation detects state inside the store.
	storeDir := filepath.Join(t.TempDir(), "store")
	stateDir := filepath.Join(storeDir, "sync")
	require.NoError(t, os.MkdirAll(stateDir, 0o755))

	err := CheckStateLocation(stateDir, storeDir)
	assert.ErrorIs(t, err, ErrStateInStore)

	// State outside the store is fine.
	otherDir := filepath.Join(t.TempDir(), "data", "binpass", "sync")
	err = CheckStateLocation(otherDir, storeDir)
	assert.NoError(t, err)
}

func TestStateDB_ParallelOps(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenStateDB(dir)
	require.NoError(t, err)
	defer db.Close()

	// Concurrent file updates should serialise through bbolt.
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func(n int) {
			defer func() { done <- struct{}{} }()
			path := filepath.Join("dir", "file.gpg")
			require.NoError(t, db.UpdateFile(&FileState{
				Path: path, Version: VersionVector{"a": uint64(n)}, Hash: hash(n),
			}))
		}(i)
	}
	for i := 0; i < 10; i++ {
		<-done
	}

	base, err := db.LoadBase()
	require.NoError(t, err)
	require.Len(t, base, 1)
}
