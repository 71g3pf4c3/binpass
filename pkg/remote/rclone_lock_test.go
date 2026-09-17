package remote

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeRcloneFS is an in-memory stand-in for the rclone binary, implementing
// the three commands the advisory lock uses. Tests drive two RcloneRemotes
// against the same fake to exercise the two-client protocol without the
// real binary.
type fakeRcloneFS struct {
	mu    sync.Mutex
	files map[string][]byte
	// onRcat, when set, runs after an rcat stores its content, with the
	// fake's mutex held. It must manipulate files directly rather than
	// call run, and exists to simulate a concurrent client overwriting the
	// lock between a writer's upload and its read-back.
	onRcat func(path string, content []byte)
}

func newFakeRcloneFS() *fakeRcloneFS {
	return &fakeRcloneFS{files: make(map[string][]byte)}
}

func (f *fakeRcloneFS) run(_ context.Context, args []string, stdin io.Reader) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch args[0] {
	case "cat":
		data, ok := f.files[args[1]]
		if !ok {
			return nil, os.ErrNotExist
		}
		return data, nil
	case "rcat":
		data, err := io.ReadAll(stdin)
		if err != nil {
			return nil, err
		}
		f.files[args[1]] = data
		if f.onRcat != nil {
			f.onRcat(args[1], data)
		}
		return nil, nil
	case "delete":
		delete(f.files, args[1])
		return nil, nil
	}
	return nil, os.ErrInvalid
}

// newFakeRclone builds an RcloneRemote whose every invocation goes to fs.
func newFakeRclone(fs *fakeRcloneFS, device string) *RcloneRemote {
	return &RcloneRemote{name: "fake", remote: "mem:", device: device, run: fs.run}
}

func TestAdvisoryLockRoundTrip(t *testing.T) {
	orig := advisoryLock{
		Device: "thinkpad",
		TS:     time.Date(2026, 8, 9, 14, 22, 33, 0, time.UTC),
		TTL:    5 * time.Minute,
	}
	parsed, err := parseAdvisoryLock(orig.marshal())
	require.NoError(t, err)
	assert.Equal(t, orig, parsed)
}

func TestAdvisoryLockParse(t *testing.T) {
	t.Run("unknown lines are ignored for forward compatibility", func(t *testing.T) {
		l, err := parseAdvisoryLock([]byte("future:field\ndevice:x\nts:2026-08-09T14:22:33Z\n"))
		require.NoError(t, err)
		assert.Equal(t, "x", l.Device)
	})
	t.Run("missing device is incomplete", func(t *testing.T) {
		_, err := parseAdvisoryLock([]byte("ts:2026-08-09T14:22:33Z\nttl:300\n"))
		assert.Error(t, err)
	})
	t.Run("missing ts is incomplete", func(t *testing.T) {
		_, err := parseAdvisoryLock([]byte("device:x\nttl:300\n"))
		assert.Error(t, err)
	})
	t.Run("missing ttl falls back to the default", func(t *testing.T) {
		l, err := parseAdvisoryLock([]byte("device:x\nts:2026-08-09T14:22:33Z\n"))
		require.NoError(t, err)
		assert.Equal(t, DefaultLockTTL, l.TTL)
	})
	t.Run("garbage ts is an error", func(t *testing.T) {
		_, err := parseAdvisoryLock([]byte("device:x\nts:not-a-time\nttl:300\n"))
		assert.Error(t, err)
	})
}

func TestAdvisoryLockStale(t *testing.T) {
	now := time.Date(2026, 8, 9, 15, 0, 0, 0, time.UTC)
	l := advisoryLock{Device: "x", TS: now.Add(-10 * time.Minute), TTL: 5 * time.Minute}
	assert.True(t, l.stale(now), "a lock outlived by its TTL is stale")
	l.TTL = 30 * time.Minute
	assert.False(t, l.stale(now), "a lock inside its TTL is live")
}

// TestRcloneRemote_AdvisoryLock exercises the two-client protocol: one lock,
// the second client is rejected; an expired lock is stolen; a released lock
// is free again.
func TestRcloneRemote_AdvisoryLock(t *testing.T) {
	ctx := context.Background()

	t.Run("second client is rejected while the first holds the lock", func(t *testing.T) {
		fs := newFakeRcloneFS()
		a := newFakeRclone(fs, "thinkpad")
		b := newFakeRclone(fs, "macbook")

		unlock, err := a.Lock(ctx)
		require.NoError(t, err)

		_, err = b.Lock(ctx)
		var held *LockHeldError
		require.ErrorAs(t, err, &held)
		assert.Equal(t, "thinkpad", held.Lock.Device)
		assert.Contains(t, held.Error(), "thinkpad", "the error names the holder")

		require.NoError(t, unlock.Unlock(ctx))
	})

	t.Run("an expired lock is stolen by the next client", func(t *testing.T) {
		fs := newFakeRcloneFS()
		// A device that died mid-sync an hour ago.
		stale := advisoryLock{Device: "corpse", TS: time.Now().Add(-time.Hour), TTL: DefaultLockTTL}
		fs.files["mem:/"+LockFileName] = stale.marshal()

		a := newFakeRclone(fs, "thinkpad")
		unlock, err := a.Lock(ctx)
		require.NoError(t, err)
		require.NoError(t, unlock.Unlock(ctx))
	})

	t.Run("a released lock is free again", func(t *testing.T) {
		fs := newFakeRcloneFS()
		a := newFakeRclone(fs, "thinkpad")
		b := newFakeRclone(fs, "macbook")

		unlock, err := a.Lock(ctx)
		require.NoError(t, err)
		require.NoError(t, unlock.Unlock(ctx))

		unlockB, err := b.Lock(ctx)
		require.NoError(t, err)
		require.NoError(t, unlockB.Unlock(ctx))
	})

	t.Run("unlock leaves a lock that is not ours alone", func(t *testing.T) {
		fs := newFakeRcloneFS()
		a := newFakeRclone(fs, "thinkpad")

		unlock, err := a.Lock(ctx)
		require.NoError(t, err)

		// Another client takes over after our lock expired.
		theirs := advisoryLock{Device: "macbook", TS: time.Now(), TTL: DefaultLockTTL}
		fs.files["mem:/"+LockFileName] = theirs.marshal()

		require.NoError(t, unlock.Unlock(ctx))
		held, ok := fs.files["mem:/"+LockFileName]
		require.True(t, ok, "the foreign lock must survive our unlock")
		parsed, err := parseAdvisoryLock(held)
		require.NoError(t, err)
		assert.Equal(t, "macbook", parsed.Device)
	})

	t.Run("a clobbered read-back loses the race", func(t *testing.T) {
		fs := newFakeRcloneFS()
		fs.onRcat = func(path string, _ []byte) {
			if path == "mem:/"+LockFileName {
				// A concurrent client's lock lands between our write
				// and our read-back.
				winner := advisoryLock{Device: "macbook", TS: time.Now(), TTL: DefaultLockTTL}
				fs.files[path] = winner.marshal()
			}
		}
		a := newFakeRclone(fs, "thinkpad")

		_, err := a.Lock(ctx)
		var held *LockHeldError
		require.ErrorAs(t, err, &held)
		assert.Equal(t, "macbook", held.Lock.Device)
	})

	t.Run("the lock file never appears in a listing", func(t *testing.T) {
		assert.False(t, IsStoreContent(LockFileName),
			"the lock is transport state, not store content")
	})
}

// TestRcloneRemote_AdvisoryLockReal runs the protocol against the real rclone
// binary over a local backend, which exercises the actual cat/rcat/delete
// commands the lock depends on. It skips when rclone is not on PATH, the same
// way the golden suite skips without pass.
func TestRcloneRemote_AdvisoryLockReal(t *testing.T) {
	if _, err := exec.LookPath("rclone"); err != nil {
		t.Skip("rclone not on PATH")
	}
	dir := t.TempDir()
	a, err := NewRcloneRemote(RcloneOptions{Name: "a", Remote: dir, Device: "thinkpad"})
	require.NoError(t, err)
	b, err := NewRcloneRemote(RcloneOptions{Name: "b", Remote: dir, Device: "macbook"})
	require.NoError(t, err)
	ctx := context.Background()

	unlock, err := a.Lock(ctx)
	require.NoError(t, err)

	_, err = b.Lock(ctx)
	var held *LockHeldError
	require.ErrorAs(t, err, &held)
	assert.Equal(t, "thinkpad", held.Lock.Device)

	require.NoError(t, unlock.Unlock(ctx))

	unlockB, err := b.Lock(ctx)
	require.NoError(t, err)
	require.NoError(t, unlockB.Unlock(ctx))
}

// TestRcloneRemote_ListReal checks List against the real rclone binary on
// the local backend. The fake-runner tests prove the parsing; only the real
// binary proves the flags — which is how a listing that filtered itself to
// nothing (--files-from-raw /dev/stdin with no input) and a listing that
// never left the top level (no -R) both shipped.
func TestRcloneRemote_ListReal(t *testing.T) {
	if _, err := exec.LookPath("rclone"); err != nil {
		t.Skip("rclone not on PATH")
	}
	dir := t.TempDir()
	nested := filepath.Join(dir, "github.com")
	require.NoError(t, os.MkdirAll(nested, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(nested, "alice.age"), []byte("data"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "toplevel.gpg"), []byte("data"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, LockFileName), []byte("lock"), 0o600))

	ctx := context.Background()
	r, err := NewRcloneRemote(RcloneOptions{Name: "local", Remote: dir})
	require.NoError(t, err)
	defer func() { _ = r.Close() }()

	files, err := r.List(ctx)
	require.NoError(t, err)

	var paths []string
	for _, f := range files {
		paths = append(paths, f.Path)
	}
	assert.ElementsMatch(t, []string{"github.com/alice.age", "toplevel.gpg"}, paths,
		"nested and top-level entries alike, and nothing that is not a store file")
}
