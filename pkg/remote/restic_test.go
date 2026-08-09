package remote

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResticRemote_Integration exercises the full ResticRemote lifecycle
// against a real restic binary and a local repository.
func TestResticRemote_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping restic integration test in short mode")
	}
	if _, err := exec.LookPath("restic"); err != nil {
		t.Skip("restic not found on PATH")
	}

	ctx := context.Background()
	storeDir, repoDir, password := setupResticRepo(t)

	r, err := NewResticRemote(ResticOptions{
		Name:     "test-local",
		Repo:     repoDir,
		Password: password,
		StoreDir: storeDir,
	})
	require.NoError(t, err)
	defer func() { _ = r.Close() }()

	// Caps should report restic capabilities.
	caps := r.Caps()
	assert.False(t, caps.Atomic)
	assert.True(t, caps.WeakAtomic)
	assert.True(t, caps.History)
	assert.True(t, caps.Rename)
	assert.False(t, caps.Watch)

	// Name.
	assert.Equal(t, "test-local", r.Name())

	// List on empty store (no snapshots) should return an error about no snapshots.
	_, err = r.List(ctx)
	assert.Error(t, err, "list on empty repo should fail with 'no snapshots found'")

	// Put a file (writes to local store, marks dirty).
	rev, err := r.Put(ctx, "sites/example.gpg", bytes.NewReader([]byte("encrypted-data")), "")
	require.NoError(t, err)
	assert.Empty(t, rev, "rev should be empty before first Push (no snapshot yet)")

	// Push creates the first snapshot.
	require.NoError(t, r.Push(ctx))

	// List should now include the file.
	files, err := r.List(ctx)
	require.NoError(t, err)
	require.Len(t, files, 1)
	assert.Equal(t, "sites/example.gpg", files[0].Path)
	assert.NotEmpty(t, files[0].Rev, "rev should be a snapshot ID")
	assert.Equal(t, int64(len("encrypted-data")), files[0].Size)

	// Get the file back.
	rc, getRev, err := r.Get(ctx, "sites/example.gpg")
	require.NoError(t, err)
	defer func() { _ = rc.Close() }()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(rc)
	assert.Equal(t, "encrypted-data", buf.String())
	assert.NotEmpty(t, getRev)

	// Put a second file and push.
	_, err = r.Put(ctx, "bank/tinkoff.gpg", bytes.NewReader([]byte("bank-data")), files[0].Rev)
	require.NoError(t, err)
	require.NoError(t, r.Push(ctx))

	files, err = r.List(ctx)
	require.NoError(t, err)
	assert.Len(t, files, 2)

	// Delete a file.
	require.NoError(t, r.Delete(ctx, "bank/tinkoff.gpg", ""))
	require.NoError(t, r.Push(ctx))

	files, err = r.List(ctx)
	require.NoError(t, err)
	assert.Len(t, files, 1)
	assert.Equal(t, "sites/example.gpg", files[0].Path)

	// Rename.
	require.NoError(t, r.Rename(ctx, "sites/example.gpg", "sites/renamed.gpg"))
	require.NoError(t, r.Push(ctx))

	files, err = r.List(ctx)
	require.NoError(t, err)
	require.Len(t, files, 1)
	assert.Equal(t, "sites/renamed.gpg", files[0].Path)

	// Snapshots should return at least one snapshot.
	snaps, err := r.Snapshots(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, snaps, "should have at least one snapshot")
	for _, s := range snaps {
		assert.NotEmpty(t, s.ShortID)
		assert.Contains(t, s.Tags, "binpass", "snapshot should have binpass tag")
	}

	// Restore latest snapshot to a temp dir.
	restoreDir := filepath.Join(t.TempDir(), "restored")
	require.NoError(t, os.MkdirAll(restoreDir, 0o755))
	require.NoError(t, r.Restore(ctx, "latest", restoreDir))
	restored, err := os.ReadFile(filepath.Join(restoreDir, "sites", "renamed.gpg"))
	require.NoError(t, err)
	assert.Equal(t, "encrypted-data", string(restored))

	// Lock is no-op.
	lock, err := r.Lock(ctx)
	require.NoError(t, err)
	require.NoError(t, lock.Unlock(ctx))

	// Pull is no-op.
	require.NoError(t, r.Pull(ctx))
}

// TestResticRemote_ConditionalWrite tests that Push fails if the snapshot has
// changed since List was called (another client pushed in the meantime).
func TestResticRemote_ConditionalWrite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping restic integration test in short mode")
	}
	if _, err := exec.LookPath("restic"); err != nil {
		t.Skip("restic not found on PATH")
	}

	ctx := context.Background()
	storeDir, repoDir, password := setupResticRepo(t)

	// Client 1.
	r1, err := NewResticRemote(ResticOptions{
		Name:     "client1",
		Repo:     repoDir,
		Password: password,
		StoreDir: storeDir,
	})
	require.NoError(t, err)
	defer func() { _ = r1.Close() }()

	// Client 1: Put + Push.
	_, err = r1.Put(ctx, "sites/a.gpg", bytes.NewReader([]byte("aaa")), "")
	require.NoError(t, err)
	require.NoError(t, r1.Push(ctx))

	// Client 2: same repo, different store dir.
	storeDir2 := t.TempDir()
	r2, err := NewResticRemote(ResticOptions{
		Name:     "client2",
		Repo:     repoDir,
		Password: password,
		StoreDir: storeDir2,
	})
	require.NoError(t, err)
	defer func() { _ = r2.Close() }()

	// Client 2: List to get the snapshot rev.
	files, err := r2.List(ctx)
	require.NoError(t, err)
	require.Len(t, files, 1)
	snapRev := files[0].Rev

	// Client 1: makes another change and pushes.
	_, err = r1.Put(ctx, "sites/b.gpg", bytes.NewReader([]byte("bbb")), snapRev)
	require.NoError(t, err)
	require.NoError(t, r1.Push(ctx))

	// Client 2: tries to Push — should fail because snapshot has changed.
	// Put without expectRev so the write succeeds locally; the conflict
	// is detected at Push time (snapshot drift since List).
	_, err = r2.Put(ctx, "sites/c.gpg", bytes.NewReader([]byte("ccc")), "")
	require.NoError(t, err)
	err = r2.Push(ctx)
	assert.Error(t, err, "Push should fail when snapshot has changed since List")
	assert.Contains(t, err.Error(), "another client")
}

// TestResticRemote_PutConditionalConflict tests that Put with a stale snapshot
// rev returns an error.
func TestResticRemote_PutConditionalConflict(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping restic integration test in short mode")
	}
	if _, err := exec.LookPath("restic"); err != nil {
		t.Skip("restic not found on PATH")
	}

	ctx := context.Background()
	storeDir, repoDir, password := setupResticRepo(t)

	r, err := NewResticRemote(ResticOptions{
		Name:     "test",
		Repo:     repoDir,
		Password: password,
		StoreDir: storeDir,
	})
	require.NoError(t, err)
	defer func() { _ = r.Close() }()

	// Create initial state.
	_, err = r.Put(ctx, "sites/a.gpg", bytes.NewReader([]byte("aaa")), "")
	require.NoError(t, err)
	require.NoError(t, r.Push(ctx))

	// List to get rev.
	files, err := r.List(ctx)
	require.NoError(t, err)
	snapRev := files[0].Rev

	// Push another change (advances the snapshot).
	_, err = r.Put(ctx, "sites/b.gpg", bytes.NewReader([]byte("bbb")), snapRev)
	require.NoError(t, err)
	require.NoError(t, r.Push(ctx))

	// Try Put with the old rev — should fail.
	_, err = r.Put(ctx, "sites/c.gpg", bytes.NewReader([]byte("ccc")), snapRev)
	assert.Error(t, err, "Put with stale rev should fail")
	assert.Contains(t, err.Error(), "conflict")
}

// TestResticRemote_Forget tests snapshot pruning.
func TestResticRemote_Forget(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping restic integration test in short mode")
	}
	if _, err := exec.LookPath("restic"); err != nil {
		t.Skip("restic not found on PATH")
	}

	ctx := context.Background()
	storeDir, repoDir, password := setupResticRepo(t)

	r, err := NewResticRemote(ResticOptions{
		Name:     "test",
		Repo:     repoDir,
		Password: password,
		StoreDir: storeDir,
	})
	require.NoError(t, err)
	defer func() { _ = r.Close() }()

	// Create 3 snapshots.
	for i := 0; i < 3; i++ {
		_, err = r.Put(ctx, "sites/a.gpg", bytes.NewReader([]byte("data")), "")
		require.NoError(t, err)
		require.NoError(t, r.Push(ctx))
	}

	snaps, err := r.Snapshots(ctx)
	require.NoError(t, err)
	assert.Len(t, snaps, 3)

	// Keep only the last snapshot.
	require.NoError(t, r.Forget(ctx, "--keep-last", "1"))

	snaps, err = r.Snapshots(ctx)
	require.NoError(t, err)
	assert.Len(t, snaps, 1)
}

// TestResticRemote_NewResticRemoteValidation tests that NewResticRemote
// validates its inputs.
func TestResticRemote_NewResticRemoteValidation(t *testing.T) {
	// Missing repo.
	_, err := NewResticRemote(ResticOptions{
		Name:     "test",
		Repo:     "",
		Password: "pw",
		StoreDir: t.TempDir(),
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "repo is required")

	// Missing store dir.
	_, err = NewResticRemote(ResticOptions{
		Name:     "test",
		Repo:     "/tmp/repo",
		Password: "pw",
		StoreDir: "",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "store directory is required")

	// Non-existent store dir.
	_, err = NewResticRemote(ResticOptions{
		Name:     "test",
		Repo:     "/tmp/repo",
		Password: "pw",
		StoreDir: "/nonexistent/path/that/does/not/exist",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "store directory")
}

// ---- helpers ----

// setupResticRepo creates a temporary store directory and a restic repository.
// It returns the store dir, the repo dir, and the password used for the repo.
func setupResticRepo(t *testing.T) (storeDir, repoDir, password string) {
	t.Helper()
	tmp := t.TempDir()
	storeDir = filepath.Join(tmp, "store")
	repoDir = filepath.Join(tmp, "repo")
	password = "binpass-test-restic"

	require.NoError(t, os.MkdirAll(storeDir, 0o755))
	require.NoError(t, os.MkdirAll(repoDir, 0o755))

	// Init the restic repo.
	cmd := exec.Command("restic", "init", "--repo", repoDir)
	cmd.Env = append(os.Environ(), "RESTIC_PASSWORD="+password)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("restic init: %s: %s", err, out)
	}

	return storeDir, repoDir, password
}
