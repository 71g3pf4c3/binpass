package tomb

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupSidecar sets BINPASS_DATA_DIR to a temp directory so state files
// don't pollute the user's real data home.
func setupSidecar(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("BINPASS_DATA_DIR", dir)
	return dir
}

// testIdentity returns an age identity and its recipient string for testing.
func testIdentity(t *testing.T) (age.Identity, string) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	return id, id.Recipient().String()
}

// setupStore creates a temporary directory simulating a password store with
// an .age-recipients file.
func setupStore(t *testing.T, rcp string) string {
	t.Helper()
	dir := t.TempDir()

	// Write .age-recipients.
	err := os.WriteFile(filepath.Join(dir, ".age-recipients"), []byte(rcp+"\n"), 0o600)
	require.NoError(t, err)

	// Write a sample entry.
	entryDir := filepath.Join(dir, "github.com")
	require.NoError(t, os.MkdirAll(entryDir, 0o700))
	err = os.WriteFile(filepath.Join(entryDir, "alice.age"), []byte("test-encrypted-content"), 0o600)
	require.NoError(t, err)

	return dir
}

func TestSelectBackend(t *testing.T) {
	tests := []struct {
		name    string
		want    Backend
		wantErr bool
	}{
		{"coffin default", BackendCoffin, false},
		{"coffin explicit", BackendCoffin, false},
		{"empty string defaults to coffin", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SelectBackend(tt.want)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			// Empty input resolves to the default backend (coffin).
			expected := tt.want
			if expected == "" {
				expected = BackendCoffin
			}
			assert.Equal(t, expected, got.Name())
		})
	}
}

func TestCoffinInit(t *testing.T) {
	_, rcp := testIdentity(t)
	dir := setupStore(t, rcp)

	c, err := newCoffin()
	require.NoError(t, err)

	err = c.Init(dir, []string{rcp}, 0)
	require.NoError(t, err)

	// The coffin file should exist.
	coffinPath := filepath.Join(dir, coffinFileName)
	info, err := os.Stat(coffinPath)
	require.NoError(t, err)
	assert.True(t, info.Size() > 0, "coffin should not be empty")

	// After init, the store content should still be there (init packs but
	// does not remove — the plaintext is the working copy).
	_, err = os.Stat(filepath.Join(dir, ".age-recipients"))
	assert.NoError(t, err, "store files should still exist after init")
}

func TestCoffinInitAlreadyExists(t *testing.T) {
	_, rcp := testIdentity(t)
	dir := setupStore(t, rcp)

	c, err := newCoffin()
	require.NoError(t, err)

	err = c.Init(dir, []string{rcp}, 0)
	require.NoError(t, err)

	// Second init should fail.
	err = c.Init(dir, []string{rcp}, 0)
	assert.Error(t, err)
}

func TestCoffinOpenNotInitialised(t *testing.T) {
	dir := t.TempDir()

	c, err := newCoffin()
	require.NoError(t, err)

	err = c.Open(dir, 0)
	assert.ErrorIs(t, err, ErrNotInitialised)
}

func TestCoffinLifecycle(t *testing.T) {
	setupSidecar(t)
	id, rcp := testIdentity(t)
	dir := setupStore(t, rcp)

	c, err := newCoffin()
	require.NoError(t, err)

	// Wire identity for decryption.
	c.SetIdentities(func() ([]age.Identity, error) {
		return []age.Identity{id}, nil
	})

	// Init: pack the store into a coffin.
	err = c.Init(dir, []string{rcp}, 0)
	require.NoError(t, err)

	// The coffin file must exist.
	coffinPath := filepath.Join(dir, coffinFileName)
	_, err = os.Stat(coffinPath)
	require.NoError(t, err)

	// Remove the plaintext entries (simulating "store is closed").
	// In real use, close would have done this. Here we remove them
	// so that open has room to unpack.
	require.NoError(t, os.RemoveAll(filepath.Join(dir, "github.com")))

	// Open: decrypt the coffin into the store directory.
	err = c.Open(dir, 0)
	require.NoError(t, err)

	// Plaintext should be back.
	_, err = os.Stat(filepath.Join(dir, ".age-recipients"))
	assert.NoError(t, err, "recipients file should be restored after open")

	// Close: re-encrypt and shred.
	err = c.Close(dir, false)
	require.NoError(t, err)

	// The coffin should still exist.
	_, err = os.Stat(coffinPath)
	assert.NoError(t, err)

	// Plaintext entries should be gone.
	_, err = os.Stat(filepath.Join(dir, "github.com"))
	assert.True(t, os.IsNotExist(err), "plaintext should be removed after close")
}

func TestCoffinDoubleOpen(t *testing.T) {
	setupSidecar(t)
	id, rcp := testIdentity(t)
	dir := setupStore(t, rcp)

	c, err := newCoffin()
	require.NoError(t, err)
	c.SetIdentities(func() ([]age.Identity, error) {
		return []age.Identity{id}, nil
	})

	err = c.Init(dir, []string{rcp}, 0)
	require.NoError(t, err)

	// Remove plaintext so we can open.
	require.NoError(t, os.RemoveAll(filepath.Join(dir, "github.com")))

	err = c.Open(dir, 0)
	require.NoError(t, err)

	// Second open should fail.
	err = c.Open(dir, 0)
	assert.ErrorIs(t, err, ErrAlreadyOpen)

	// Clean up.
	_ = c.Close(dir, true)
}

func TestCoffinCloseNotOpen(t *testing.T) {
	dir := t.TempDir()

	c, err := newCoffin()
	require.NoError(t, err)

	err = c.Close(dir, false)
	assert.ErrorIs(t, err, ErrNotOpen)
}

func TestCoffinStatus(t *testing.T) {
	setupSidecar(t)
	id, rcp := testIdentity(t)
	dir := setupStore(t, rcp)

	c, err := newCoffin()
	require.NoError(t, err)
	c.SetIdentities(func() ([]age.Identity, error) {
		return []age.Identity{id}, nil
	})

	// Before init: not open.
	_, isOpen, err := c.Status(dir)
	require.NoError(t, err)
	assert.False(t, isOpen)

	// Init.
	err = c.Init(dir, []string{rcp}, 0)
	require.NoError(t, err)

	// Init packs the store but leaves the plaintext in place, so the tomb is
	// open in the only sense that matters: the entries are readable. Calling
	// that "closed" is what let `tomb close` claim success on a store it had
	// never protected.
	_, isOpen, err = c.Status(dir)
	require.NoError(t, err)
	assert.True(t, isOpen, "the entries are still in plaintext, so the tomb is open")

	// Remove plaintext and open.
	require.NoError(t, os.RemoveAll(filepath.Join(dir, "github.com")))
	err = c.Open(dir, 0)
	require.NoError(t, err)

	// Now it should be open.
	st, isOpen, err := c.Status(dir)
	require.NoError(t, err)
	assert.True(t, isOpen)
	assert.Equal(t, BackendCoffin, st.Backend)

	// Close.
	_ = c.Close(dir, true)
	_, isOpen, err = c.Status(dir)
	require.NoError(t, err)
	assert.False(t, isOpen)
}

func TestStateStale(t *testing.T) {
	// PID 999999 almost certainly does not exist.
	s := State{PID: 999999}
	assert.True(t, s.IsStale(), "dead PID should be stale")

	// PID 0 is never considered stale (no process to check).
	s = State{PID: 0}
	assert.False(t, s.IsStale(), "PID 0 should not be stale")
}

func TestStateRoundTrip(t *testing.T) {
	setupSidecar(t)
	dir := t.TempDir()

	now := time.Now().Truncate(time.Second) // JSON loses sub-second precision.
	s := State{
		Backend:  BackendCoffin,
		StoreDir: dir,
		OpenedAt: now,
		Timer:    30 * time.Minute,
		PID:      os.Getpid(),
	}

	err := saveState(dir, &s)
	require.NoError(t, err)

	loaded, err := loadState(dir)
	require.NoError(t, err)

	assert.Equal(t, s.Backend, loaded.Backend)
	assert.Equal(t, s.StoreDir, loaded.StoreDir)
	assert.Equal(t, s.Timer, loaded.Timer)
	assert.Equal(t, s.PID, loaded.PID)
	assert.Equal(t, s.OpenedAt.Unix(), loaded.OpenedAt.Unix())
}

func TestStateMissing(t *testing.T) {
	setupSidecar(t)
	dir := t.TempDir()
	_, err := loadState(dir)
	assert.True(t, os.IsNotExist(err))
}

func TestShredDir(t *testing.T) {
	dir := t.TempDir()

	// Create some test files.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "secret.age"), []byte("hunter2"), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "subdir"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "subdir", "nested.age"), []byte("nested-secret"), 0o600))

	// Create the file that should be preserved.
	preserveFile := "store.coffin.age"
	require.NoError(t, os.WriteFile(filepath.Join(dir, preserveFile), []byte("encrypted"), 0o600))

	err := shredDir(dir, true, preserveFile)
	require.NoError(t, err)

	// The preserved file should still exist.
	_, err = os.Stat(filepath.Join(dir, preserveFile))
	assert.NoError(t, err, "preserved file should survive shred")

	// Everything else should be gone.
	_, err = os.Stat(filepath.Join(dir, "secret.age"))
	assert.True(t, os.IsNotExist(err))
	_, err = os.Stat(filepath.Join(dir, "subdir"))
	assert.True(t, os.IsNotExist(err))
}

func TestHasPlaintext(t *testing.T) {
	t.Run("empty directory", func(t *testing.T) {
		dir := t.TempDir()
		assert.False(t, hasPlaintext(dir))
	})

	t.Run("only coffin", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, coffinFileName), []byte("x"), 0o600))
		assert.False(t, hasPlaintext(dir))
	})

	t.Run("dotfile only", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, ".gitignore"), []byte("x"), 0o600))
		assert.False(t, hasPlaintext(dir))
	})

	t.Run("plaintext present", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "github.age"), []byte("x"), 0o600))
		assert.True(t, hasPlaintext(dir))
	})
}
