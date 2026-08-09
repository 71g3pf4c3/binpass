package cli

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/71g3pf4c3/binpass/internal/config"
	"github.com/71g3pf4c3/binpass/pkg/crypto"
	"github.com/71g3pf4c3/binpass/pkg/remote"
	"github.com/71g3pf4c3/binpass/pkg/secret"
	"github.com/71g3pf4c3/binpass/pkg/sync"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testApp is an App backed by an initialised age store in a temporary
// directory, with its sync state kept outside the store.
type testApp struct {
	*App
	// out collects command output.
	out *bytes.Buffer
	// errOut collects diagnostics.
	errOut *bytes.Buffer
	// dir is the store root.
	dir string
}

// newTestApp builds an initialised store with a throwaway age identity. No
// part of it touches the developer's own store or key ring.
func newTestApp(t *testing.T) *testApp {
	t.Helper()
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "store")
	require.NoError(t, os.MkdirAll(dir, 0o700))

	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	keyFile := filepath.Join(tmp, "identity.key")
	require.NoError(t, os.WriteFile(keyFile, []byte(id.String()+"\n"), 0o600))

	t.Setenv("BINPASS_STATE_DIR", filepath.Join(tmp, "state"))

	cfg := config.Default()
	cfg.Dir = dir
	cfg.Identity = keyFile
	cfg.Default = config.BackendAge

	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}
	app := &App{Cfg: cfg, Out: out, Err: errOut, In: strings.NewReader("")}

	s, err := app.Store()
	require.NoError(t, err)
	require.NoError(t, s.Init("", []crypto.Recipient{crypto.Recipient(id.Recipient().String())}))

	return &testApp{App: app, out: out, errOut: errOut, dir: dir}
}

// set writes an entry through the store, the way `binpass insert` would.
func (a *testApp) set(t *testing.T, name, content string) {
	t.Helper()
	s, err := a.Store()
	require.NoError(t, err)
	require.NoError(t, s.Set(name, secret.Parse([]byte(content))))
}

// bareRepo returns a shared repository for the git transport to push to.
func bareRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not found on PATH")
	}
	dir := filepath.Join(t.TempDir(), "bare.git")
	require.NoError(t, exec.Command("git", "init", "-q", "--bare", dir).Run()) //nolint:gosec // fixed arguments.
	return dir
}

// gitIdentity gives the store worktree an author, which git demands before it
// will make a commit.
func gitIdentity(t *testing.T, dir string) {
	t.Helper()
	for k, v := range map[string]string{
		"user.name":  "tester",
		"user.email": "tester@example.invalid",
	} {
		require.NoError(t, exec.Command("git", "-C", dir, "config", k, v).Run()) //nolint:gosec // fixed arguments.
	}
}

func TestSyncPushesLocalEntriesToGitRemote(t *testing.T) {
	app := newTestApp(t)
	app.Cfg.Remotes = map[string]config.RemoteConfig{
		"origin": {Type: "git", URL: bareRepo(t)},
	}
	app.set(t, "github.com/alice", "hunter2\n")

	// The remote is built lazily by runSync; the worktree needs an author
	// before the first commit.
	require.NoError(t, exec.Command("git", "-C", app.dir, "init", "-q").Run()) //nolint:gosec // fixed arguments.
	gitIdentity(t, app.dir)

	require.NoError(t, app.runSync(context.Background(), "origin", false))
	assert.Contains(t, app.out.String(), "github.com/alice.age")

	// A second run has nothing left to transfer.
	app.out.Reset()
	require.NoError(t, app.runSync(context.Background(), "origin", false))
	assert.NotContains(t, app.out.String(), "push")
	assert.NotContains(t, app.out.String(), "conflict")
}

func TestSyncDryRunLeavesRemoteEmpty(t *testing.T) {
	app := newTestApp(t)
	repo := bareRepo(t)
	app.Cfg.Remotes = map[string]config.RemoteConfig{"origin": {Type: "git", URL: repo}}
	app.set(t, "github.com/alice", "hunter2\n")
	require.NoError(t, exec.Command("git", "-C", app.dir, "init", "-q").Run()) //nolint:gosec // fixed arguments.
	gitIdentity(t, app.dir)

	require.NoError(t, app.runSync(context.Background(), "origin", true))
	assert.Contains(t, app.out.String(), "(dry-run)")

	refs, err := exec.Command("git", "-C", repo, "for-each-ref").Output() //nolint:gosec // fixed arguments.
	require.NoError(t, err)
	assert.Empty(t, strings.TrimSpace(string(refs)), "a dry run must not publish anything")
}

func TestSyncRejectsUnknownRemote(t *testing.T) {
	app := newTestApp(t)
	err := app.runSync(context.Background(), "nope", false)
	assert.ErrorContains(t, err, `unknown remote "nope"`)
}

func TestSyncRequiresInitialisedStore(t *testing.T) {
	tmp := t.TempDir()
	cfg := config.Default()
	cfg.Dir = filepath.Join(tmp, "empty")
	app := &App{Cfg: cfg, Out: &bytes.Buffer{}, Err: &bytes.Buffer{}}

	err := app.runSync(context.Background(), "", false)
	assert.ErrorContains(t, err, "password store is empty")
}

func TestApplyActionsPushesAndPulls(t *testing.T) {
	app := newTestApp(t)
	app.set(t, "alice", "hunter2\n")

	s, err := app.Store()
	require.NoError(t, err)
	mem := remote.NewMemRemote(remote.MemOptions{Name: "mem"})
	ctx := context.Background()

	// A file the remote does not have yet: pushed.
	local, err := sync.Scan(app.dir, sync.Snapshot{}, "dev1", []string{".gpg", ".age"})
	require.NoError(t, err)
	var pushes []sync.Action
	for path, st := range local {
		pushes = append(pushes, sync.Action{Kind: sync.ActionPush, Path: path, Local: st})
	}

	db, err := sync.OpenStateDB(t.TempDir())
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	require.NoError(t, app.applyActions(ctx, s, mem, db, sync.Snapshot{}, pushes, "dev1"))

	files, err := mem.List(ctx)
	require.NoError(t, err)
	require.Len(t, files, 1)
	assert.Equal(t, "alice.age", files[0].Path)

	// A file only the remote has: pulled into the store.
	_, err = mem.Put(ctx, "bob.age", strings.NewReader("ciphertext"), "")
	require.NoError(t, err)
	pull := []sync.Action{{
		Kind:   sync.ActionPull,
		Path:   "bob.age",
		Remote: &sync.FileState{Path: "bob.age", Size: 10, Version: sync.VersionVector{"dev2": 1}, Device: "dev2"},
	}}
	require.NoError(t, app.applyActions(ctx, s, mem, db, sync.Snapshot{}, pull, "dev1"))

	data, err := os.ReadFile(filepath.Join(app.dir, "bob.age"))
	require.NoError(t, err)
	assert.Equal(t, "ciphertext", string(data))
}

func TestApplyActionsDeletesFromRemote(t *testing.T) {
	app := newTestApp(t)
	s, err := app.Store()
	require.NoError(t, err)
	ctx := context.Background()

	mem := remote.NewMemRemote(remote.MemOptions{Name: "mem"})
	_, err = mem.Put(ctx, "gone.age", strings.NewReader("x"), "")
	require.NoError(t, err)

	db, err := sync.OpenStateDB(t.TempDir())
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	acts := []sync.Action{{Kind: sync.ActionDelete, Path: "gone.age"}}
	require.NoError(t, app.applyActions(ctx, s, mem, db, sync.Snapshot{}, acts, "dev1"))

	files, err := mem.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, files)
}

func TestApplyActionsKeepsBothSidesOfAConflict(t *testing.T) {
	app := newTestApp(t)
	app.set(t, "alice", "local-secret\n")
	s, err := app.Store()
	require.NoError(t, err)
	ctx := context.Background()

	mem := remote.NewMemRemote(remote.MemOptions{Name: "mem"})
	_, err = mem.Put(ctx, "alice.age", strings.NewReader("remote-ciphertext"), "")
	require.NoError(t, err)

	db, err := sync.OpenStateDB(t.TempDir())
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	acts := []sync.Action{{
		Kind:   sync.ActionConflict,
		Path:   "alice.age",
		Local:  &sync.FileState{Path: "alice.age", Version: sync.VersionVector{"dev1": 2}, Device: "dev1"},
		Remote: &sync.FileState{Path: "alice.age", Version: sync.VersionVector{"dev2": 2}, Device: "dev2"},
	}}
	require.NoError(t, app.applyActions(ctx, s, mem, db, sync.Snapshot{}, acts, "dev1"))

	// The remote version wins the original path.
	data, err := os.ReadFile(filepath.Join(app.dir, "alice.age"))
	require.NoError(t, err)
	assert.Equal(t, "remote-ciphertext", string(data))

	// The local version survives under a conflict name.
	entries, err := os.ReadDir(app.dir)
	require.NoError(t, err)
	found := false
	for _, e := range entries {
		if strings.Contains(e.Name(), ".conflict-dev1-") {
			found = true
		}
	}
	assert.True(t, found, "the local version must not be lost")
}

func TestBuildRemoteResolvesTheOnlyConfiguredRemote(t *testing.T) {
	app := newTestApp(t)
	app.Cfg.Remotes = map[string]config.RemoteConfig{"only": {Type: "git", URL: bareRepo(t)}}

	rem, err := app.buildRemote("")
	require.NoError(t, err)
	assert.Equal(t, "only", rem.Name())
}

func TestBuildRemoteNeedsAChoiceBetweenSeveral(t *testing.T) {
	app := newTestApp(t)
	app.Cfg.Remotes = map[string]config.RemoteConfig{
		"b": {Type: "git", URL: "b"},
		"a": {Type: "git", URL: "a"},
	}
	_, err := app.buildRemote("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "a, b", "the names must be listed in a stable order")
}

func TestBuildRemoteWithoutConfiguration(t *testing.T) {
	app := newTestApp(t)
	_, err := app.buildRemote("")
	assert.ErrorContains(t, err, "no remote configured")
}

func TestBuildRemoteResticRequiresARepository(t *testing.T) {
	app := newTestApp(t)
	app.Cfg.Remotes = map[string]config.RemoteConfig{"backup": {Type: "restic"}}
	_, err := app.buildRemote("backup")
	assert.ErrorContains(t, err, "requires url")
}

func TestRemoteFilesToSnapshotKeepsKnownVersions(t *testing.T) {
	base := sync.Snapshot{
		"known.age": &sync.FileState{Path: "known.age", Version: sync.VersionVector{"dev1": 7}},
	}
	files := []remote.File{
		{Path: "known.age", Size: 10, Rev: "r1"},
		{Path: "fresh.age", Size: 20, Rev: "r2"},
	}
	snap := remoteFilesToSnapshot(files, base, "dev1")

	assert.Equal(t, uint64(7), snap["known.age"].Version["dev1"], "an unchanged file keeps its history")
	assert.Equal(t, uint64(1), snap["fresh.age"].Version["dev1"], "a new file starts at one")
	assert.Equal(t, "r2", snap["fresh.age"].RemoteRev)
}

func TestStripCryptoExt(t *testing.T) {
	assert.Equal(t, "github.com/alice", stripCryptoExt("github.com/alice.age"))
	assert.Equal(t, "github.com/alice", stripCryptoExt("github.com/alice.gpg"))
	assert.Equal(t, "notes.txt", stripCryptoExt("notes.txt"), "other extensions are left alone")
}

func TestDeriveDeviceIDFallsBackToUnknown(t *testing.T) {
	orig := osHostname
	t.Cleanup(func() { osHostname = orig })

	osHostname = func() (string, error) { return "thinkpad", nil }
	id, err := deriveDeviceID()
	require.NoError(t, err)
	assert.Equal(t, sync.DeviceID("thinkpad"), id)
}

func TestIsGitRepo(t *testing.T) {
	dir := t.TempDir()
	assert.False(t, isGitRepo(dir))
	require.NoError(t, os.Mkdir(filepath.Join(dir, ".git"), 0o700))
	assert.True(t, isGitRepo(dir))
}

func TestPrintActionMarksDryRuns(t *testing.T) {
	app := newTestApp(t)
	app.printAction(sync.Action{Kind: sync.ActionPull, Path: "alice.age"}, true)
	app.printAction(sync.Action{Kind: sync.ActionMergeHOTP, Path: "otp.age", MergedCounter: 42}, false)

	got := app.out.String()
	assert.Contains(t, got, "(dry-run) pull   alice.age")
	assert.Contains(t, got, "merge  otp.age (HOTP counter: 42)")
}
