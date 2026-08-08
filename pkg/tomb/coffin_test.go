package tomb

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Tar round-trip tests ---

func TestWriteAndReadTar(t *testing.T) {
	// Create a source directory with files, subdirs, symlinks.
	src := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(src, "sub"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(src, "root.age"), []byte("root-content"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(src, "sub", "nested.age"), []byte("nested"), 0o600))
	require.NoError(t, os.Symlink("root.age", filepath.Join(src, "link")))

	// Write tar.
	var buf bytes.Buffer
	require.NoError(t, writeTar(&buf, src))

	// Read tar into a new directory.
	dst := t.TempDir()
	require.NoError(t, readTar(&buf, dst))

	// Verify contents.
	data, err := os.ReadFile(filepath.Join(dst, "root.age"))
	require.NoError(t, err)
	assert.Equal(t, "root-content", string(data))

	data, err = os.ReadFile(filepath.Join(dst, "sub", "nested.age"))
	require.NoError(t, err)
	assert.Equal(t, "nested", string(data))

	// Verify symlink target (not the file contents).
	link, err := os.Readlink(filepath.Join(dst, "link"))
	require.NoError(t, err)
	assert.Equal(t, "root.age", link)
}

func TestWriteTarSkipsDotfiles(t *testing.T) {
	src := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(src, ".gitignore"), []byte("x"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(src, "visible.age"), []byte("y"), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(src, ".git"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(src, ".git", "config"), []byte("z"), 0o600))

	var buf bytes.Buffer
	require.NoError(t, writeTar(&buf, src))

	// Parse the tar and check entries.
	tr := tar.NewReader(&buf)
	var names []string
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		names = append(names, h.Name)
	}
	assert.Contains(t, names, "visible.age")
	assert.NotContains(t, names, ".gitignore")
	assert.NotContains(t, names, ".git/config")
}

func TestWriteTarSkipsCoffin(t *testing.T) {
	src := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(src, coffinFileName), []byte("coffin"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(src, "entry.age"), []byte("data"), 0o600))

	var buf bytes.Buffer
	require.NoError(t, writeTar(&buf, src))

	tr := tar.NewReader(&buf)
	var names []string
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		names = append(names, h.Name)
	}
	assert.Contains(t, names, "entry.age")
	assert.NotContains(t, names, coffinFileName)
}

func TestReadTarPathTraversal(t *testing.T) {
	// Craft a tar with a traversal entry.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "../../etc/passwd", Typeflag: tar.TypeReg, Size: 6}))
	_, _ = tw.Write([]byte("root:x"))
	require.NoError(t, tw.Close())

	dst := t.TempDir()
	err := readTar(&buf, dst)
	assert.Error(t, err, "path traversal should be rejected")
}

// --- Coffin encrypt/decrypt with age ---

func TestCoffinEncryptDecryptRoundTrip(t *testing.T) {
	setupSidecar(t)
	id, rcp := testIdentity(t)
	dir := setupStore(t, rcp)

	c, err := newCoffin()
	require.NoError(t, err)
	c.SetIdentities(func() ([]age.Identity, error) {
		return []age.Identity{id}, nil
	})

	// Init: pack into coffin.
	require.NoError(t, c.Init(dir, []string{rcp}, 0))

	// Remove plaintext.
	require.NoError(t, os.RemoveAll(filepath.Join(dir, "github.com")))

	// Open: decrypt and verify.
	require.NoError(t, c.Open(dir, 0))
	_, err = os.Stat(filepath.Join(dir, "github.com", "alice.age"))
	assert.NoError(t, err, "entry should be restored after open")

	// Close: re-encrypt and verify plaintext is gone.
	require.NoError(t, c.Close(dir, false))
	_, err = os.Stat(filepath.Join(dir, "github.com"))
	assert.True(t, os.IsNotExist(err), "plaintext should be gone after close")
}

func TestCoffinPreservesFilePermissions(t *testing.T) {
	setupSidecar(t)
	id, rcp := testIdentity(t)
	dir := t.TempDir()

	// Write .age-recipients.
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".age-recipients"), []byte(rcp+"\n"), 0o600))

	// Create an entry with specific permissions.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "secret.age"), []byte("data"), 0o600))

	c, err := newCoffin()
	require.NoError(t, err)
	c.SetIdentities(func() ([]age.Identity, error) {
		return []age.Identity{id}, nil
	})

	require.NoError(t, c.Init(dir, []string{rcp}, 0))
	require.NoError(t, os.Remove(filepath.Join(dir, "secret.age")))
	require.NoError(t, c.Open(dir, 0))

	info, err := os.Stat(filepath.Join(dir, "secret.age"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	_ = c.Close(dir, true)
}

func TestCoffinCloseWithModifiedContent(t *testing.T) {
	setupSidecar(t)
	id, rcp := testIdentity(t)
	dir := setupStore(t, rcp)

	c, err := newCoffin()
	require.NoError(t, err)
	c.SetIdentities(func() ([]age.Identity, error) {
		return []age.Identity{id}, nil
	})

	require.NoError(t, c.Init(dir, []string{rcp}, 0))
	require.NoError(t, os.RemoveAll(filepath.Join(dir, "github.com")))
	require.NoError(t, c.Open(dir, 0))

	// Modify the plaintext while open.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "new-entry.age"), []byte("new"), 0o600))

	// Close should re-encrypt including the new entry.
	require.NoError(t, c.Close(dir, false))

	// Re-open and verify new entry survived.
	require.NoError(t, c.Open(dir, 0))
	_, err = os.Stat(filepath.Join(dir, "new-entry.age"))
	assert.NoError(t, err, "new entry should survive close/open cycle")

	_ = c.Close(dir, true)
}

// --- Watcher tests ---

func TestWatcherTimerFires(t *testing.T) {
	setupSidecar(t)
	closed := false
	w := NewWatcher("/tmp/test-store", 50*time.Millisecond, func(dir string) error {
		closed = true
		return nil
	})
	defer w.Stop()

	// Wait for the timer to fire.
	time.Sleep(100 * time.Millisecond)
	assert.True(t, closed, "timer should have triggered close")
}

func TestWatcherNoTimer(t *testing.T) {
	w := NewWatcher("/tmp/test-store", 0, func(dir string) error {
		return nil
	})
	// Should not panic. Stop should return immediately.
	w.Stop()
}

func TestWatcherStopPreventsClose(t *testing.T) {
	closed := false
	w := NewWatcher("/tmp/test-store", 100*time.Millisecond, func(dir string) error {
		closed = true
		return nil
	})

	// Stop before timer fires.
	time.Sleep(10 * time.Millisecond)
	w.Stop()

	// Wait past the timer.
	time.Sleep(150 * time.Millisecond)
	assert.False(t, closed, "stop should prevent close")
}

func TestWatcherDoubleTrigger(t *testing.T) {
	called := 0
	w := NewWatcher("/tmp/test-store", 10*time.Millisecond, func(dir string) error {
		called++
		return nil
	})
	defer w.Stop()

	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, 1, called, "close should fire exactly once")
}

// --- DoctorCheck test ---

func TestDoctorCheck(t *testing.T) {
	// Just verify it doesn't panic and returns a non-empty string.
	result := DoctorCheck()
	assert.NotEmpty(t, result)
}

// --- FormatWatcherStatus tests ---

func TestFormatWatcherStatus(t *testing.T) {
	assert.Contains(t, FormatWatcherStatus(0), "disabled")
	assert.Contains(t, FormatWatcherStatus(30*time.Minute), "timer")
}

// --- isWithin test ---

func TestIsWithin(t *testing.T) {
	assert.True(t, isWithin("/home/user/store", "/home/user/store/entry.age"))
	assert.True(t, isWithin("/home/user/store", "/home/user/store"))
	assert.False(t, isWithin("/home/user/store", "/home/user/other/entry.age"))
}

// --- overwriteRandom test ---

func TestOverwriteRandom(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test")
	require.NoError(t, os.WriteFile(path, []byte("sensitive-data"), 0o600))

	err := overwriteRandom(path, 14)
	require.NoError(t, err)

	// File should still exist (overwrite, not remove).
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, int64(14), info.Size())
}

// --- Crash recovery test ---

func TestCoffinCrashRecovery(t *testing.T) {
	setupSidecar(t)
	id, rcp := testIdentity(t)
	dir := setupStore(t, rcp)

	c, err := newCoffin()
	require.NoError(t, err)
	c.SetIdentities(func() ([]age.Identity, error) {
		return []age.Identity{id}, nil
	})

	require.NoError(t, c.Init(dir, []string{rcp}, 0))
	require.NoError(t, os.RemoveAll(filepath.Join(dir, "github.com")))
	require.NoError(t, c.Open(dir, 0))

	// Simulate crash: leave state file but remove plaintext.
	// This happens when the process is killed before close.
	_ = os.RemoveAll(filepath.Join(dir, "github.com"))
	_ = os.Remove(statePath(dir))

	// The next open should succeed (state is gone, no plaintext).
	require.NoError(t, c.Open(dir, 0))

	_ = c.Close(dir, true)
}
