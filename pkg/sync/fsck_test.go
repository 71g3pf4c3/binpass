package sync

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lukechampine.com/blake3"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFsck_CleanStore(t *testing.T) {
	storeDir := t.TempDir()
	stateDir := t.TempDir()

	db, err := OpenStateDB(stateDir)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	results, err := Fsck(storeDir, stateDir, db)
	require.NoError(t, err)
	assert.Empty(t, results, "clean store should have no issues")
}

func TestFsck_UntrackedFile(t *testing.T) {
	storeDir := t.TempDir()
	stateDir := t.TempDir()

	// Create an encrypted file on disk.
	require.NoError(t, os.MkdirAll(filepath.Join(storeDir, "sites"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(storeDir, "sites", "example.gpg"), []byte("data"), 0o644))

	db, err := OpenStateDB(stateDir)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	results, err := Fsck(storeDir, stateDir, db)
	require.NoError(t, err)
	// Untracked file + missing recipients = 2 warnings.
	untrackedFound := false
	for _, r := range results {
		if r.Path == filepath.Join("sites", "example.gpg") {
			untrackedFound = true
			assert.Equal(t, "warning", r.Severity)
			assert.Contains(t, r.Issue, "untracked")
		}
	}
	assert.True(t, untrackedFound, "should report untracked file")
}

func TestFsck_OrphanedState(t *testing.T) {
	storeDir := t.TempDir()
	stateDir := t.TempDir()

	db, err := OpenStateDB(stateDir)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	// Put a file in state.db that doesn't exist on disk.
	fs := &FileState{
		Path:    "missing.gpg",
		Size:    42,
		Device:  DeviceID("test-device"),
		Version: VersionVector{DeviceID("test-device"): 1},
	}
	require.NoError(t, db.UpdateFile(fs))

	results, err := Fsck(storeDir, stateDir, db)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "warning", results[0].Severity)
	assert.Contains(t, results[0].Issue, "orphaned")
	assert.Equal(t, "missing.gpg", results[0].Path)
}

func TestFsck_SizeDrift(t *testing.T) {
	storeDir := t.TempDir()
	stateDir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(storeDir, "changed.gpg"), []byte("some content here"), 0o644))

	db, err := OpenStateDB(stateDir)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	// Record different size in state.db.
	fs := &FileState{
		Path:    "changed.gpg",
		Size:    999,
		Device:  DeviceID("test-device"),
		Version: VersionVector{DeviceID("test-device"): 1},
	}
	require.NoError(t, db.UpdateFile(fs))

	results, err := Fsck(storeDir, stateDir, db)
	require.NoError(t, err)
	// Size drift + missing recipients = 2 warnings.
	driftFound := false
	for _, r := range results {
		if r.Path == "changed.gpg" {
			driftFound = true
			assert.Equal(t, "warning", r.Severity)
			assert.Contains(t, r.Issue, "size drift")
		}
	}
	assert.True(t, driftFound, "should report size drift")
}

func TestFsck_StateInStore(t *testing.T) {
	storeDir := t.TempDir()
	// stateDir is inside storeDir — critical error.
	stateDir := filepath.Join(storeDir, ".local", "state", "binpass")

	require.NoError(t, os.MkdirAll(stateDir, 0o755))

	db, err := OpenStateDB(stateDir)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	results, err := Fsck(storeDir, stateDir, db)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "error", results[0].Severity)
	assert.Contains(t, results[0].Issue, "inside the password store")
}

func TestFsck_MissingRecipients(t *testing.T) {
	storeDir := t.TempDir()
	stateDir := t.TempDir()

	// Create encrypted file but no .gpg-id or .age-recipients.
	require.NoError(t, os.WriteFile(filepath.Join(storeDir, "entry.gpg"), []byte("data"), 0o644))

	db, err := OpenStateDB(stateDir)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	results, err := Fsck(storeDir, stateDir, db)
	require.NoError(t, err)

	// Should report: untracked + missing recipients.
	found := false
	for _, r := range results {
		if r.Path == ".gpg-id / .age-recipients" {
			found = true
			assert.Equal(t, "warning", r.Severity)
			assert.Contains(t, r.Issue, "no recipient file")
		}
	}
	assert.True(t, found, "expected missing recipients warning")
}

func TestFsck_ConflictFileForOrphan(t *testing.T) {
	storeDir := t.TempDir()
	stateDir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(storeDir, "site.gpg.conflict-laptop-20260808.gpg"), []byte("data"), 0o644))

	db, err := OpenStateDB(stateDir)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	// Put an orphaned entry whose conflict file exists.
	fs := &FileState{
		Path:    "site.gpg",
		Size:    42,
		Device:  DeviceID("laptop"),
		Version: VersionVector{DeviceID("laptop"): 1},
	}
	require.NoError(t, db.UpdateFile(fs))

	results, err := Fsck(storeDir, stateDir, db)
	require.NoError(t, err)

	// Should report: orphaned entry + conflict file.
	orphanFound := false
	conflictFound := false
	for _, r := range results {
		if r.Path == "site.gpg" && r.Severity == "warning" {
			orphanFound = true
		}
		if r.Path == "site.gpg.conflict-laptop-20260808.gpg" {
			conflictFound = true
		}
	}
	assert.True(t, orphanFound, "should report orphaned entry")
	assert.True(t, conflictFound, "should report conflict file for orphan")
}

func TestFsck_HashDrift(t *testing.T) {
	storeDir := t.TempDir()
	stateDir := t.TempDir()

	// Write a file on disk.
	filePath := filepath.Join(storeDir, "changed.gpg")
	require.NoError(t, os.WriteFile(filePath, []byte("original content"), 0o644))

	db, err := OpenStateDB(stateDir)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	// Record the file in state.db with the same size but different hash.
	// Compute the hash of "original content".
	origHash := blake3.Sum256([]byte("original content"))

	fs := &FileState{
		Path:    "changed.gpg",
		Size:    17, // same size as "original content"
		Hash:    origHash,
		Device:  DeviceID("test-device"),
		Version: VersionVector{DeviceID("test-device"): 1},
	}
	require.NoError(t, db.UpdateFile(fs))

	// Now change the file on disk to something of the same size but
	// different content. "differentcontent" is also 17 bytes.
	require.NoError(t, os.WriteFile(filePath, []byte("differentcontent"), 0o644))

	results, err := Fsck(storeDir, stateDir, db)
	require.NoError(t, err)

	hashDriftFound := false
	for _, r := range results {
		if r.Path == "changed.gpg" && strings.Contains(r.Issue, "hash drift") {
			hashDriftFound = true
			assert.Equal(t, "warning", r.Severity)
		}
	}
	assert.True(t, hashDriftFound, "should report hash drift when content changes at same size")
}
