//go:build darwin

package tomb

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/71g3pf4c3/binpass/pkg/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestBundle returns a SparseBundle wired to a fake runner and a
// throwaway age identity, plus the recipient to encrypt to.
func newTestBundle(t *testing.T) (*SparseBundle, *fakeRunner, string) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	f := &fakeRunner{fail: map[string]error{}, output: map[string][]byte{}}
	s := &SparseBundle{runner: f.run}
	s.SetIdentities(func() ([]age.Identity, error) { return []age.Identity{id}, nil })
	return s, f, id.Recipient().String()
}

func TestBundleInitCreatesAnEncryptedImage(t *testing.T) {
	s, f, rcp := newTestBundle(t)
	dir := storeWithState(t)

	require.NoError(t, s.Init(dir, []string{rcp}, 64<<20))

	create := f.find("hdiutil", "create")
	require.NotNil(t, create)
	assert.Contains(t, create.args, "-encryption")
	assert.Contains(t, create.args, bundlePath(dir))

	// The passphrase reaches hdiutil on stdin, never as an argument.
	assert.NotEmpty(t, create.stdin)
	for _, a := range create.args {
		assert.NotContains(t, a, string(create.stdin))
	}

	assert.FileExists(t, bundleKeyPath(dir), "the passphrase must be stored, or the bundle is lost")
}

func TestBundleInitNeverWritesThePassphraseInTheClear(t *testing.T) {
	s, f, rcp := newTestBundle(t)
	dir := storeWithState(t)

	require.NoError(t, s.Init(dir, []string{rcp}, 64<<20))
	pass := f.find("hdiutil", "create").stdin
	require.NotEmpty(t, pass)

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, rerr := os.ReadFile(path) //nolint:gosec // a temp dir the test made.
		if rerr != nil {
			return rerr
		}
		assert.NotContains(t, string(data), string(pass),
			"the passphrase must not appear in %s", path)
		return nil
	})
	require.NoError(t, err)

	// And it must be recoverable, or the bundle can never be opened again.
	got, err := s.readPassphrase(bundleKeyPath(dir))
	require.NoError(t, err)
	assert.Equal(t, pass, got)
}

func TestBundleInitRefusesToOverwrite(t *testing.T) {
	s, _, rcp := newTestBundle(t)
	dir := storeWithState(t)

	require.NoError(t, s.Init(dir, []string{rcp}, 64<<20))
	err := s.Init(dir, []string{rcp}, 64<<20)
	assert.ErrorContains(t, err, "already exists")
}

func TestBundleInitRejectsATinyImage(t *testing.T) {
	s, _, rcp := newTestBundle(t)
	dir := storeWithState(t)

	err := s.Init(dir, []string{rcp}, 1024)
	assert.ErrorContains(t, err, "too small")
}

func TestBundleInitCleansUpAfterAFailedCreate(t *testing.T) {
	s, f, rcp := newTestBundle(t)
	dir := storeWithState(t)
	f.fail["hdiutil"] = errors.New("exit status 1")

	require.Error(t, s.Init(dir, []string{rcp}, 64<<20))

	// A passphrase with no bundle is worse than nothing: the next init
	// refuses, and the key opens something that does not exist.
	assert.NoFileExists(t, bundlePath(dir))
	assert.NoFileExists(t, bundleKeyPath(dir))
}

func TestBundleInitMovesExistingEntriesInside(t *testing.T) {
	s, f, rcp := newTestBundle(t)
	dir := storeWithState(t)

	require.NoError(t, os.MkdirAll(filepath.Join(dir, "github.com"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "github.com", "alice.age"), []byte("ciphertext"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".age-recipients"), []byte(rcp+"\n"), 0o600))

	require.NoError(t, s.Init(dir, []string{rcp}, 64<<20))

	assert.NoFileExists(t, filepath.Join(dir, "github.com", "alice.age"),
		"a copy left outside the bundle defeats the purpose")
	assert.FileExists(t, filepath.Join(dir, ".age-recipients"), "dotfiles stay")
	assert.Contains(t, f.names(), "hdiutil")
}

func TestBundleOpenAttachesAtTheStore(t *testing.T) {
	s, f, rcp := newTestBundle(t)
	dir := storeWithState(t)
	require.NoError(t, s.Init(dir, []string{rcp}, 64<<20))
	f.calls = nil

	require.NoError(t, s.Open(dir, 30*time.Minute))

	attach := f.find("hdiutil", "attach")
	require.NotNil(t, attach)
	assert.Contains(t, attach.args, "-mountpoint")
	assert.Contains(t, attach.args, dir)
	assert.NotEmpty(t, attach.stdin, "the passphrase goes in on stdin")

	st, err := LoadState(dir)
	require.NoError(t, err)
	assert.Equal(t, BackendSparseBundle, st.Backend)
	assert.Equal(t, 30*time.Minute, st.Timer)
	assert.Equal(t, os.Getpid(), st.PID)
}

// TestBundleOpenWithoutATimerRecordsNoPID: without a timer the command
// returns immediately, so recording its PID would make status call every
// cleanly opened tomb a crash — the bug both other backends had.
func TestBundleOpenWithoutATimerRecordsNoPID(t *testing.T) {
	s, _, rcp := newTestBundle(t)
	dir := storeWithState(t)
	require.NoError(t, s.Init(dir, []string{rcp}, 64<<20))

	require.NoError(t, s.Open(dir, 0))

	st, err := LoadState(dir)
	require.NoError(t, err)
	assert.Zero(t, st.PID)
	assert.False(t, st.IsStale())
}

func TestBundleOpenWithoutABundle(t *testing.T) {
	s, _, _ := newTestBundle(t)
	dir := storeWithState(t)
	assert.ErrorIs(t, s.Open(dir, 0), ErrNotInitialised)
}

func TestBundleOpenWithoutIdentities(t *testing.T) {
	s, _, rcp := newTestBundle(t)
	dir := storeWithState(t)
	require.NoError(t, s.Init(dir, []string{rcp}, 64<<20))

	s.SetIdentities(nil)
	assert.ErrorIs(t, s.Open(dir, 0), crypto.ErrNoIdentity)
}

func TestBundleCloseWhenNothingIsAttached(t *testing.T) {
	s, _, _ := newTestBundle(t)
	dir := storeWithState(t)
	assert.ErrorIs(t, s.Close(dir, false), ErrNotOpen)
}

func TestBundleStatusWithoutABundle(t *testing.T) {
	s, _, _ := newTestBundle(t)
	dir := storeWithState(t)

	st, open, err := s.Status(dir)
	require.NoError(t, err)
	assert.False(t, open)
	assert.Empty(t, st.Backend)
}

// TestBundleAgainstRealHdiutil runs the whole cycle against the real tool.
// It only runs on macOS with hdiutil present, which is where it means
// anything.
func TestBundleAgainstRealHdiutil(t *testing.T) {
	if _, err := exec.LookPath("hdiutil"); err != nil {
		t.Skip("hdiutil not found on PATH")
	}

	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	dir := storeWithState(t)
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".age-recipients"),
		[]byte(id.Recipient().String()+"\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "entry.age"), []byte("ciphertext"), 0o600))

	s, err := newSparseBundle()
	require.NoError(t, err)
	s.SetIdentities(func() ([]age.Identity, error) { return []age.Identity{id}, nil })

	require.NoError(t, s.Init(dir, []string{id.Recipient().String()}, 64<<20))
	t.Cleanup(func() { _ = s.Close(dir, true) })

	assert.NoFileExists(t, filepath.Join(dir, "entry.age"), "init moves entries inside")

	require.NoError(t, s.Open(dir, 0))
	data, err := os.ReadFile(filepath.Join(dir, "entry.age"))
	require.NoError(t, err)
	assert.Equal(t, "ciphertext", string(data))

	require.NoError(t, s.Close(dir, false))
	assert.NoFileExists(t, filepath.Join(dir, "entry.age"))
	assert.DirExists(t, bundlePath(dir))
}
