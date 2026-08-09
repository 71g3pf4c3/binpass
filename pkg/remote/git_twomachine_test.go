package remote

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// machine is one store pointed at a shared bare repository, standing in for a
// laptop or a phone.
type machine struct {
	dir    string
	remote *GitRemote
}

// newMachine returns a store directory wired to the bare repo at url, the way
// `binpass remote add git origin URL` leaves it.
func newMachine(t *testing.T, name, url string) *machine {
	t.Helper()
	dir := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.MkdirAll(dir, 0o700))

	r, err := NewGitRemote(GitOptions{Name: "origin", Dir: dir, URL: url})
	require.NoError(t, err, "remote add must work on a directory that is not yet a repository")

	for k, v := range map[string]string{
		"user.name":  name,
		"user.email": name + "@example.invalid",
	} {
		require.NoError(t, exec.Command("git", "-C", dir, "config", k, v).Run()) //nolint:gosec // fixed arguments.
	}
	return &machine{dir: dir, remote: r}
}

// write puts an entry in the store the way an ordinary binpass command would:
// straight to the filesystem, with git knowing nothing about it.
func (m *machine) write(t *testing.T, path, content string) {
	t.Helper()
	full := filepath.Join(m.dir, path)
	require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o700))
	require.NoError(t, os.WriteFile(full, []byte(content), 0o600))
}

// paths returns the store entries the remote reports.
func (m *machine) paths(t *testing.T) []string {
	t.Helper()
	files, err := m.remote.List(context.Background())
	require.NoError(t, err)
	out := make([]string, 0, len(files))
	for _, f := range files {
		out = append(out, f.Path)
	}
	return out
}

// bareRepo returns a shared remote repository.
func bareRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not found on PATH")
	}
	dir := filepath.Join(t.TempDir(), "bare.git")
	require.NoError(t, exec.Command("git", "init", "-q", "--bare", dir).Run()) //nolint:gosec // fixed arguments.
	return dir
}

// push publishes an entry: what sync does after the merge engine decides.
func (m *machine) push(t *testing.T, path, content string) {
	t.Helper()
	ctx := context.Background()
	_, err := m.remote.Put(ctx, path, strings.NewReader(content), "")
	require.NoError(t, err)
	require.NoError(t, m.remote.Push(ctx))
}

// TestSecondMachineReceivesTheStore covers the failure that made sync delete
// data: a machine whose store has no history yet, against a remote that
// already has entries. Listing must report the remote's entries, because an
// empty listing is read by the merge engine as "everything was deleted".
func TestSecondMachineReceivesTheStore(t *testing.T) {
	url := bareRepo(t)

	alice := newMachine(t, "alice", url)
	alice.push(t, "web/site.age", "alice-secret")

	bob := newMachine(t, "bob", url)
	assert.Equal(t, []string{"web/site.age"}, bob.paths(t),
		"a fresh store must receive the remote's entries, not report them missing")

	data, err := os.ReadFile(filepath.Join(bob.dir, "web", "site.age"))
	require.NoError(t, err)
	assert.Equal(t, "alice-secret", string(data), "the content must reach the working tree")
}

// TestFreshStoreWithLocalSetupFiles covers the same case when `binpass init`
// has already written a recipients file, which makes a plain checkout refuse
// to overwrite untracked files.
func TestFreshStoreWithLocalSetupFiles(t *testing.T) {
	url := bareRepo(t)

	alice := newMachine(t, "alice", url)
	alice.push(t, ".age-recipients", "age1alice\n")
	alice.push(t, "web/site.age", "alice-secret")

	bob := newMachine(t, "bob", url)
	bob.write(t, ".age-recipients", "age1bob\n")

	assert.Equal(t, []string{"web/site.age"}, bob.paths(t),
		"local setup files must not stop the store from arriving")
}

// TestLocalEditsSurviveAPull is the failure that broke sync for anyone who
// used binpass between syncs: ordinary commands write to the working tree
// without committing, and `git pull --rebase` refuses to run with unstaged
// changes.
func TestLocalEditsSurviveAPull(t *testing.T) {
	url := bareRepo(t)

	alice := newMachine(t, "alice", url)
	alice.push(t, "web/site.age", "alice-secret")

	bob := newMachine(t, "bob", url)
	require.Equal(t, []string{"web/site.age"}, bob.paths(t))

	// Bob adds an entry the way `binpass insert` does.
	bob.write(t, "mail/work.age", "bob-secret")

	paths := bob.paths(t)
	assert.Contains(t, paths, "mail/work.age", "a local entry must survive the pull")
	assert.Contains(t, paths, "web/site.age", "and the remote's entries must still be there")
}

// TestDivergedEditKeepsBothVersions is the one that matters most: two
// machines edit the same entry offline. Git cannot merge ciphertext, and
// whatever the resolution is, neither password may vanish.
func TestDivergedEditKeepsBothVersions(t *testing.T) {
	url := bareRepo(t)

	alice := newMachine(t, "alice", url)
	alice.push(t, "web/site.age", "original")

	bob := newMachine(t, "bob", url)
	require.Equal(t, []string{"web/site.age"}, bob.paths(t))

	// Both edit offline; alice publishes first.
	alice.push(t, "web/site.age", "alice-v2")
	bob.write(t, "web/site.age", "bob-v2")

	_ = bob.paths(t)

	current, err := os.ReadFile(filepath.Join(bob.dir, "web", "site.age"))
	require.NoError(t, err)
	assert.Equal(t, "alice-v2", string(current), "the remote version takes the original path")

	// The conflict file is looked for on disk rather than in List, which
	// reports only what git tracks: the copy is written to the working tree
	// and committed by the next sync. What matters here is that the local
	// password still exists somewhere.
	entries, err := os.ReadDir(filepath.Join(bob.dir, "web"))
	require.NoError(t, err)

	var conflict string
	for _, e := range entries {
		if strings.Contains(e.Name(), ".conflict-") {
			conflict = e.Name()
		}
	}
	require.NotEmpty(t, conflict, "the local version must be preserved as a conflict file")

	kept, err := os.ReadFile(filepath.Join(bob.dir, "web", conflict))
	require.NoError(t, err)
	assert.Equal(t, "bob-v2", string(kept), "the local password must not be destroyed")
}

// TestDeleteOfAMissingFileIsNotAnError guards against one stale state entry
// blocking every future sync.
func TestDeleteOfAMissingFileIsNotAnError(t *testing.T) {
	url := bareRepo(t)
	alice := newMachine(t, "alice", url)
	alice.push(t, "web/site.age", "secret")

	assert.NoError(t, alice.remote.Delete(context.Background(), "never/existed.age", ""),
		"removing something already absent is the requested state, not a failure")
}

// TestPushWithoutARemoteIsNotSilentlySkipped pins the behaviour that hid a
// failure to publish: `git remote` exits zero and prints nothing when none is
// configured, so testing only the exit status reported success.
func TestPushWithoutARemoteIsNotSilentlySkipped(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not found on PATH")
	}
	dir := t.TempDir()
	require.NoError(t, exec.Command("git", "init", "-q", dir).Run()) //nolint:gosec // fixed arguments.

	r, err := NewGitRemote(GitOptions{Name: "origin", Dir: dir})
	require.NoError(t, err)
	assert.False(t, r.hasRemote(context.Background()),
		"a repository with no remotes must not be reported as having one")
}

// TestSyncedEntriesArePrivate guards the permissions of everything a
// transport writes.
//
// pass creates entries with a 077 umask. A transport writing them at 0644
// would silently widen access to every entry it synchronised, handing the
// ciphertext of the whole store to any other user on the machine. Nothing
// about that failure is visible in normal use.
func TestSyncedEntriesArePrivate(t *testing.T) {
	url := bareRepo(t)

	alice := newMachine(t, "alice", url)
	alice.push(t, "web/site.age", "secret")

	bob := newMachine(t, "bob", url)
	require.Equal(t, []string{"web/site.age"}, bob.paths(t))

	fi, err := os.Stat(filepath.Join(bob.dir, "web", "site.age"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm(),
		"a synced entry must be no more readable than one binpass wrote itself")

	di, err := os.Stat(filepath.Join(bob.dir, "web"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), di.Mode().Perm(),
		"and neither must the directory holding it")
}
