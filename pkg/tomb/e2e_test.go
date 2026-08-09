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

// e2eHelper sets up a full test environment for end-to-end tomb tests: age
// identity, store directory with recipients, and a wired Coffin backend.
type e2eHelper struct {
	t       *testing.T
	id      age.Identity
	rcp     string
	dir     string
	coffin  *Coffin
	sidecar string
}

// newE2EHelper creates a fresh test environment.
func newE2EHelper(t *testing.T) *e2eHelper {
	t.Helper()

	// Generate a fresh age identity.
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	rcp := id.Recipient().String()

	// Sidecar for state files (isolated from user's real data).
	sidecar := t.TempDir()
	t.Setenv("BINPASS_DATA_DIR", sidecar)

	// Store directory.
	dir := t.TempDir()

	// Write .age-recipients.
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".age-recipients"), []byte(rcp+"\n"), 0o600))

	// Create sample entries.
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "github.com"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "github.com", "alice.age"), []byte("hunter2\nusername: alice\n"), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "bank"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bank", "tinkoff.age"), []byte("s3cur3!\nusername: bob\n"), 0o600))

	c, err := newCoffin()
	require.NoError(t, err)
	c.SetIdentities(func() ([]age.Identity, error) {
		return []age.Identity{id}, nil
	})

	return &e2eHelper{t: t, id: id, rcp: rcp, dir: dir, coffin: c, sidecar: sidecar}
}

// removePlaintext simulates a closed tomb by removing all non-dotfile,
// non-coffin entries, matching the store's definition of "plaintext".
func (h *e2eHelper) removePlaintext() {
	h.t.Helper()
	entries, err := os.ReadDir(h.dir)
	require.NoError(h.t, err)
	for _, e := range entries {
		name := e.Name()
		if name[0] == '.' || name == coffinFileName {
			continue
		}
		require.NoError(h.t, os.RemoveAll(filepath.Join(h.dir, name)))
	}
}

// assertPlaintextGone checks that no plaintext entries exist in the store.
func (h *e2eHelper) assertPlaintextGone() {
	h.t.Helper()
	_, err := os.Stat(filepath.Join(h.dir, "github.com"))
	assert.True(h.t, os.IsNotExist(err), "github.com/ should not exist after close")
	_, err = os.Stat(filepath.Join(h.dir, "bank"))
	assert.True(h.t, os.IsNotExist(err), "bank/ should not exist after close")
}

// assertPlaintextPresent checks that plaintext entries exist in the store.
func (h *e2eHelper) assertPlaintextPresent() {
	h.t.Helper()
	_, err := os.Stat(filepath.Join(h.dir, "github.com", "alice.age"))
	assert.NoError(h.t, err, "github.com/alice.age should exist after open")
	_, err = os.Stat(filepath.Join(h.dir, "bank", "tinkoff.age"))
	assert.NoError(h.t, err, "bank/tinkoff.age should exist after open")
}

// --- E2E: Full lifecycle ---

func TestE2E_FullLifecycle(t *testing.T) {
	h := newE2EHelper(t)

	// Phase 1: Init creates the coffin archive.
	require.NoError(t, h.coffin.Init(h.dir, []string{h.rcp}, 0))
	coffinPath := filepath.Join(h.dir, coffinFileName)
	info, err := os.Stat(coffinPath)
	require.NoError(t, err)
	t.Logf("coffin created: %d bytes", info.Size())

	// Plaintext is still present (init packs but does not remove).
	h.assertPlaintextPresent()

	// Phase 2: Simulate "closed" state by removing plaintext.
	h.removePlaintext()

	// Phase 3: Open decrypts and extracts.
	require.NoError(t, h.coffin.Open(h.dir, 0))
	h.assertPlaintextPresent()

	// Verify content of a specific entry.
	data, err := os.ReadFile(filepath.Join(h.dir, "github.com", "alice.age"))
	require.NoError(t, err)
	assert.Equal(t, "hunter2\nusername: alice\n", string(data))

	// Phase 4: Status reports open.
	st, isOpen, err := h.coffin.Status(h.dir)
	require.NoError(t, err)
	assert.True(t, isOpen)
	assert.Equal(t, BackendCoffin, st.Backend)
	assert.Equal(t, h.dir, st.StoreDir)
	// No PID is recorded without a timer: `binpass tomb open` exits at once,
	// so a stored PID would make every clean open look like a crash.
	assert.Zero(t, st.PID)
	assert.False(t, st.IsStale())

	// Phase 5: Close re-encrypts and shreds.
	require.NoError(t, h.coffin.Close(h.dir, false))
	h.assertPlaintextGone()

	// Phase 6: Status reports closed.
	_, isOpen, err = h.coffin.Status(h.dir)
	require.NoError(t, err)
	assert.False(t, isOpen)

	// Phase 7: Coffin still exists and is non-empty.
	info, err = os.Stat(coffinPath)
	require.NoError(t, err)
	assert.True(t, info.Size() > 0, "coffin should survive close")
}

// --- E2E: Content modifications survive close/open ---

func TestE2E_ContentModificationsSurviveCycle(t *testing.T) {
	h := newE2EHelper(t)

	require.NoError(t, h.coffin.Init(h.dir, []string{h.rcp}, 0))
	h.removePlaintext()
	require.NoError(t, h.coffin.Open(h.dir, 0))

	// Modify an existing entry.
	require.NoError(t, os.WriteFile(filepath.Join(h.dir, "github.com", "alice.age"),
		[]byte("new-password\nusername: alice\n"), 0o600))

	// Add a new entry.
	require.NoError(t, os.MkdirAll(filepath.Join(h.dir, "social"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(h.dir, "social", "twitter.age"),
		[]byte("tweet-secure\n"), 0o600))

	// Close and reopen.
	require.NoError(t, h.coffin.Close(h.dir, false))
	h.assertPlaintextGone()

	require.NoError(t, h.coffin.Open(h.dir, 0))

	// Verify modified entry.
	data, err := os.ReadFile(filepath.Join(h.dir, "github.com", "alice.age"))
	require.NoError(t, err)
	assert.Equal(t, "new-password\nusername: alice\n", string(data))

	// Verify new entry.
	data, err = os.ReadFile(filepath.Join(h.dir, "social", "twitter.age"))
	require.NoError(t, err)
	assert.Equal(t, "tweet-secure\n", string(data))

	_ = h.coffin.Close(h.dir, true)
}

// --- E2E: Deleted entries do not reappear after close/open ---

func TestE2E_DeletedEntriesDisappear(t *testing.T) {
	h := newE2EHelper(t)

	require.NoError(t, h.coffin.Init(h.dir, []string{h.rcp}, 0))
	h.removePlaintext()
	require.NoError(t, h.coffin.Open(h.dir, 0))

	// Delete an entry while the tomb is open.
	require.NoError(t, os.Remove(filepath.Join(h.dir, "bank", "tinkoff.age")))
	require.NoError(t, os.Remove(filepath.Join(h.dir, "bank"))) // prune empty dir

	require.NoError(t, h.coffin.Close(h.dir, false))
	require.NoError(t, h.coffin.Open(h.dir, 0))

	// The deleted entry should stay gone.
	_, err := os.Stat(filepath.Join(h.dir, "bank", "tinkoff.age"))
	assert.True(t, os.IsNotExist(err), "deleted entry should not reappear")

	_ = h.coffin.Close(h.dir, true)
}

// --- E2E: Multiple open/close cycles ---

func TestE2E_MultipleCycles(t *testing.T) {
	h := newE2EHelper(t)

	require.NoError(t, h.coffin.Init(h.dir, []string{h.rcp}, 0))
	h.removePlaintext()

	for i := 0; i < 3; i++ {
		t.Logf("cycle %d: open", i+1)
		require.NoError(t, h.coffin.Open(h.dir, 0))
		h.assertPlaintextPresent()

		// Mutate in each cycle.
		require.NoError(t, os.WriteFile(
			filepath.Join(h.dir, "github.com", "alice.age"),
			[]byte("cycle-"+string(rune('0'+i+1))+"\n"),
			0o600))

		t.Logf("cycle %d: close", i+1)
		require.NoError(t, h.coffin.Close(h.dir, false))
		h.assertPlaintextGone()
	}

	// Final open: verify last mutation stuck.
	require.NoError(t, h.coffin.Open(h.dir, 0))
	data, err := os.ReadFile(filepath.Join(h.dir, "github.com", "alice.age"))
	require.NoError(t, err)
	assert.Equal(t, "cycle-3\n", string(data))

	_ = h.coffin.Close(h.dir, true)
}

// --- E2E: Double open is rejected ---

func TestE2E_DoubleOpenRejected(t *testing.T) {
	h := newE2EHelper(t)

	require.NoError(t, h.coffin.Init(h.dir, []string{h.rcp}, 0))
	h.removePlaintext()
	require.NoError(t, h.coffin.Open(h.dir, 0))

	err := h.coffin.Open(h.dir, 0)
	assert.ErrorIs(t, err, ErrAlreadyOpen)

	_ = h.coffin.Close(h.dir, true)
}

// --- E2E: Close without open is rejected ---

func TestE2E_CloseWithoutOpenRejected(t *testing.T) {
	dir := t.TempDir()
	c, err := newCoffin()
	require.NoError(t, err)

	err = c.Close(dir, false)
	assert.ErrorIs(t, err, ErrNotOpen)
}

// --- E2E: Open without init is rejected ---

func TestE2E_OpenWithoutInitRejected(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BINPASS_DATA_DIR", t.TempDir())

	c, err := newCoffin()
	require.NoError(t, err)

	err = c.Open(dir, 0)
	assert.ErrorIs(t, err, ErrNotInitialised)
}

// --- E2E: Crash recovery — stale state is cleaned up ---

func TestE2E_CrashRecovery(t *testing.T) {
	h := newE2EHelper(t)

	require.NoError(t, h.coffin.Init(h.dir, []string{h.rcp}, 0))
	h.removePlaintext()
	require.NoError(t, h.coffin.Open(h.dir, 0))

	// Simulate a crash: process dies without calling Close.
	// The state file is left behind with a dead PID.
	require.NoError(t, saveState(h.dir, &State{
		Backend:    BackendCoffin,
		StoreDir:   h.dir,
		CoffinPath: filepath.Join(h.dir, coffinFileName),
		OpenedAt:   time.Now(),
		PID:        999999, // guaranteed dead
	}))

	// Remove the plaintext (as if the OS killed the process
	// and the decrypted dir was lost).
	require.NoError(t, os.RemoveAll(filepath.Join(h.dir, "github.com")))
	require.NoError(t, os.RemoveAll(filepath.Join(h.dir, "bank")))

	// A new process opening the tomb should detect the stale state,
	// clean it up, and succeed.
	require.NoError(t, h.coffin.Open(h.dir, 0))
	h.assertPlaintextPresent()

	_ = h.coffin.Close(h.dir, true)
}

// --- E2E: After close, no plaintext remains on disk ---

func TestE2E_NoPlaintextAfterClose(t *testing.T) {
	h := newE2EHelper(t)

	require.NoError(t, h.coffin.Init(h.dir, []string{h.rcp}, 0))
	h.removePlaintext()
	require.NoError(t, h.coffin.Open(h.dir, 0))
	require.NoError(t, h.coffin.Close(h.dir, false))

	// Walk the store directory and verify no .age or .gpg files remain
	// outside the coffin. Only the coffin and dotfiles should survive.
	err := filepath.WalkDir(h.dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		// The coffin file itself has .age extension; skip it.
		if name == coffinFileName {
			return nil
		}
		ext := filepath.Ext(name)
		if ext == ".age" || ext == ".gpg" {
			t.Errorf("plaintext file survived close: %s", path)
		}
		return nil
	})
	require.NoError(t, err)
}

// --- E2E: State file is cleaned up after close ---

func TestE2E_StateFileCleanedUpAfterClose(t *testing.T) {
	h := newE2EHelper(t)

	require.NoError(t, h.coffin.Init(h.dir, []string{h.rcp}, 0))
	h.removePlaintext()
	require.NoError(t, h.coffin.Open(h.dir, 0))

	// State file should exist.
	sp := statePath(h.dir)
	_, err := os.Stat(sp)
	require.NoError(t, err, "state file should exist while open")

	require.NoError(t, h.coffin.Close(h.dir, false))

	// State file should be gone.
	_, err = os.Stat(sp)
	assert.True(t, os.IsNotExist(err), "state file should be removed after close")
}

// --- E2E: Timer auto-close works ---

func TestE2E_TimerAutoClose(t *testing.T) {
	h := newE2EHelper(t)

	require.NoError(t, h.coffin.Init(h.dir, []string{h.rcp}, 0))
	h.removePlaintext()
	require.NoError(t, h.coffin.Open(h.dir, 0))

	// Start a watcher with a short timer.
	closed := make(chan struct{})
	w := NewWatcher(h.dir, 50*time.Millisecond, func(dir string) error {
		_ = h.coffin.Close(dir, true)
		close(closed)
		return nil
	})

	// Wait for auto-close.
	select {
	case <-closed:
		// Success.
	case <-time.After(2 * time.Second):
		t.Fatal("auto-close timer did not fire within timeout")
	}
	w.Stop()

	h.assertPlaintextGone()
}

// --- E2E: Shred actually overwrites file data ---

func TestE2E_ShredOverwritesData(t *testing.T) {
	dir := t.TempDir()
	secret := "this-is-sensitive-data-that-should-be-overwritten"
	secretPath := filepath.Join(dir, "secret.age")
	require.NoError(t, os.WriteFile(secretPath, []byte(secret), 0o600))

	// Record the original content offset (inode).
	originalStat, err := os.Stat(secretPath)
	require.NoError(t, err)
	originalSize := originalStat.Size()

	// Overwrite with random data.
	require.NoError(t, overwriteRandom(secretPath, originalSize))

	// Read back and verify the content is no longer the secret.
	data, err := os.ReadFile(secretPath)
	require.NoError(t, err)
	assert.NotEqual(t, secret, string(data), "data should be overwritten")
	assert.Equal(t, int(originalSize), len(data), "size should be preserved")
}

// --- E2E: Empty store can be initialised and cycled ---

func TestE2E_EmptyStore(t *testing.T) {
	h := newE2EHelper(t)

	// Remove the sample entries, leaving only .age-recipients.
	require.NoError(t, os.RemoveAll(filepath.Join(h.dir, "github.com")))
	require.NoError(t, os.RemoveAll(filepath.Join(h.dir, "bank")))

	// Init should work even with no entries.
	require.NoError(t, h.coffin.Init(h.dir, []string{h.rcp}, 0))

	// Verify the coffin was created (tar of just .age-recipients).
	coffinPath := filepath.Join(h.dir, coffinFileName)
	info, err := os.Stat(coffinPath)
	require.NoError(t, err)
	assert.True(t, info.Size() > 0, "coffin of empty store should be non-empty (contains recipients)")

	// Close should work (no entries to re-encrypt, but recipients are there).
	// Since there's no plaintext, we can't "open" (nothing to extract from
	// the tar — .age-recipients is a dotfile, skipped by writeTar).
	// But the coffin contains .age-recipients via the tar.
}

// --- E2E: Store with nested directories preserves structure ---

func TestE2E_NestedDirectoryStructure(t *testing.T) {
	h := newE2EHelper(t)

	// Create deeply nested entries.
	nested := filepath.Join(h.dir, "a", "b", "c")
	require.NoError(t, os.MkdirAll(nested, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(nested, "deep.age"), []byte("deep-value\n"), 0o600))

	require.NoError(t, h.coffin.Init(h.dir, []string{h.rcp}, 0))
	h.removePlaintext()
	require.NoError(t, h.coffin.Open(h.dir, 0))

	data, err := os.ReadFile(filepath.Join(h.dir, "a", "b", "c", "deep.age"))
	require.NoError(t, err)
	assert.Equal(t, "deep-value\n", string(data))

	_ = h.coffin.Close(h.dir, true)
}

// --- E2E: SelectBackend rejects unknown backends ---

func TestE2E_SelectBackendRejectsUnknown(t *testing.T) {
	_, err := SelectBackend("nonexistent")
	assert.Error(t, err)
}

// --- E2E: DefaultBackend returns coffin ---

func TestE2E_DefaultBackendIsCoffin(t *testing.T) {
	assert.Equal(t, BackendCoffin, DefaultBackend())
}

// --- E2E: Coffin Init with missing recipients fails ---

func TestE2E_InitWithNoRecipientsFails(t *testing.T) {
	h := newE2EHelper(t)

	err := h.coffin.Init(h.dir, []string{}, 0)
	assert.Error(t, err, "init with no recipients should fail")
}

// --- E2E: Tar preserves Unix permissions ---

func TestE2E_TarPreservesPermissions(t *testing.T) {
	h := newE2EHelper(t)

	// Set specific permissions on an entry.
	entryPath := filepath.Join(h.dir, "github.com", "alice.age")
	require.NoError(t, os.Chmod(entryPath, 0o640))

	require.NoError(t, h.coffin.Init(h.dir, []string{h.rcp}, 0))
	h.removePlaintext()
	require.NoError(t, h.coffin.Open(h.dir, 0))

	info, err := os.Stat(entryPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o640), info.Mode().Perm(),
		"file permissions should be preserved through tar round-trip")

	_ = h.coffin.Close(h.dir, true)
}

// TestCleanOpenIsNotReportedAsACrash guards a status that told the user their
// tomb had crashed every time it opened normally.
//
// The PID was recorded from `binpass tomb open`, a command that exits as soon
// as the store is unpacked, so the process was always gone by the time anyone
// ran `tomb status`. A warning that fires on the ordinary path trains people
// to ignore it, which is worse than not warning at all.
func TestCleanOpenIsNotReportedAsACrash(t *testing.T) {
	h := newE2EHelper(t)

	require.NoError(t, h.coffin.Init(h.dir, []string{h.rcp}, 0))
	require.NoError(t, h.coffin.Close(h.dir, true))
	require.NoError(t, h.coffin.Open(h.dir, 0))

	st, err := loadState(h.dir)
	require.NoError(t, err)
	assert.False(t, st.IsStale(),
		"a tomb opened without a timer must not report a crash once the command exits")
}
