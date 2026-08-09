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

// TestGitRemote_Integration tests the GitRemote against a real git repository.
// It requires git on PATH and is skipped in short mode.
func TestGitRemote_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping git integration test in short mode")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not found on PATH")
	}

	ctx := context.Background()
	storeDir, _ := setupGitRepo(t)

	g, err := NewGitRemote(GitOptions{
		Name: "origin",
		Dir:  storeDir,
	})
	require.NoError(t, err)
	defer func() { _ = g.Close() }()

	// Caps should report git capabilities.
	caps := g.Caps()
	assert.True(t, caps.Atomic)
	assert.True(t, caps.History)
	assert.True(t, caps.Rename)

	// List on empty store should return nothing (no committed files yet).
	files, err := g.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, files)

	// Put a new file.
	rev1, err := g.Put(ctx, "github.com/alice.gpg", bytes.NewReader([]byte("encrypted-alice")), "")
	require.NoError(t, err)
	assert.NotEmpty(t, rev1, "first commit should return a non-empty rev")

	// List should now include the file.
	files, err = g.List(ctx)
	require.NoError(t, err)
	require.Len(t, files, 1)
	assert.Equal(t, "github.com/alice.gpg", files[0].Path)
	assert.NotEmpty(t, files[0].Rev)

	// Get the file back.
	rc, rev, err := g.Get(ctx, "github.com/alice.gpg")
	require.NoError(t, err)
	defer func() { _ = rc.Close() }()
	assert.Equal(t, rev1, rev)

	// Put a second file in a subdirectory.
	_, err = g.Put(ctx, "bank/tinkoff.gpg", bytes.NewReader([]byte("encrypted-bank")), "")
	require.NoError(t, err)

	files, err = g.List(ctx)
	require.NoError(t, err)
	assert.Len(t, files, 2)

	// Edit the first file (conditional write with correct rev).
	rev2, err := g.Put(ctx, "github.com/alice.gpg", bytes.NewReader([]byte("updated-alice")), rev1)
	require.NoError(t, err)
	assert.NotEqual(t, rev1, rev2, "edit should produce a new rev")

	// Conditional write with wrong rev should fail.
	_, err = g.Put(ctx, "github.com/alice.gpg", bytes.NewReader([]byte("stale")), "wrong-rev")
	assert.Error(t, err, "conditional write with wrong rev should fail")

	// Rename a file.
	err = g.Rename(ctx, "github.com/alice.gpg", "github.com/bob.gpg")
	require.NoError(t, err)

	files, err = g.List(ctx)
	require.NoError(t, err)
	paths := make(map[string]bool, len(files))
	for _, f := range files {
		paths[f.Path] = true
	}
	assert.True(t, paths["github.com/bob.gpg"], "renamed file should exist")
	assert.False(t, paths["github.com/alice.gpg"], "old name should not exist")

	// Delete a file.
	err = g.Delete(ctx, "github.com/bob.gpg", "")
	require.NoError(t, err)

	files, err = g.List(ctx)
	require.NoError(t, err)
	assert.Len(t, files, 1)
	assert.Equal(t, "bank/tinkoff.gpg", files[0].Path)

	// Verify commit messages match pass format.
	log, err := gitLog(storeDir)
	require.NoError(t, err)
	assert.Contains(t, log, "Add given password for github.com/alice to store.")
	assert.Contains(t, log, "Add given password for bank/tinkoff to store.")
	assert.Contains(t, log, "Edit password for github.com/alice using binpass.")
	assert.Contains(t, log, "Rename github.com/alice to github.com/bob.")
	assert.Contains(t, log, "Remove github.com/bob from store.")
}

// TestGitRemote_PassCompatible verifies that a repository created and
// maintained by binpass's GitRemote is readable by the real pass(1).
func TestGitRemote_PassCompatible(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping git integration test in short mode")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not found on PATH")
	}

	ctx := context.Background()
	storeDir, _ := setupGitRepo(t)

	g, err := NewGitRemote(GitOptions{
		Name: "origin",
		Dir:  storeDir,
	})
	require.NoError(t, err)
	defer func() { _ = g.Close() }()

	// Put a file via GitRemote.
	_, err = g.Put(ctx, "sites/example.gpg", bytes.NewReader([]byte("test-content")), "")
	require.NoError(t, err)

	// Verify the file is in the git working tree.
	workingCopy := filepath.Join(storeDir, "sites", "example.gpg")
	data, err := os.ReadFile(workingCopy)
	require.NoError(t, err)
	assert.Equal(t, "test-content", string(data))

	// Verify git log has pass-compatible messages.
	log, err := gitLog(storeDir)
	require.NoError(t, err)
	assert.Contains(t, log, "Add given password for sites/example to store.")
}

// setupGitRepo creates a temporary directory with a git repo initialised as
// pass would do it (with user.name and user.email set), and returns the store
// directory and the bare remote directory.
func setupGitRepo(t *testing.T) (storeDir, bareDir string) {
	t.Helper()
	tmp := t.TempDir()
	storeDir = filepath.Join(tmp, "store")
	bareDir = filepath.Join(tmp, "bare.git")

	require.NoError(t, os.MkdirAll(storeDir, 0o755))

	// Init the store as a git repo.
	runGit(t, storeDir, "init")
	runGit(t, storeDir, "config", "user.name", "binpass-test")
	runGit(t, storeDir, "config", "user.email", "test@binpass.dev")

	// Create an initial commit so HEAD exists.
	dotGitAttributes := filepath.Join(storeDir, ".gitattributes")
	require.NoError(t, os.WriteFile(dotGitAttributes, []byte("*.gpg binary\n*.age binary\n"), 0o644))
	runGit(t, storeDir, "add", ".gitattributes")
	runGit(t, storeDir, "commit", "-m", "Configure gitattributes for binary files")

	// Init a bare remote and add it as origin.
	require.NoError(t, os.MkdirAll(bareDir, 0o755))
	runGit(t, bareDir, "init", "--bare")
	runGit(t, storeDir, "remote", "add", "origin", bareDir)

	return storeDir, bareDir
}

// runGit executes a git command in the given directory.
func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s in %s: %s: %s", args, dir, err, out)
	}
}

// gitLog returns the full commit log.
func gitLog(dir string) (string, error) {
	cmd := exec.Command("git", "log", "--oneline")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// TestGitRemote_PushPull tests Push and Pull with a bare repo as the remote.
func TestGitRemote_PushPull(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping git integration test in short mode")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not found on PATH")
	}

	ctx := context.Background()
	tmp := t.TempDir()
	storeDir := filepath.Join(tmp, "store")
	bareDir := filepath.Join(tmp, "bare.git")

	require.NoError(t, os.MkdirAll(bareDir, 0o755))
	runGit(t, bareDir, "init", "--bare")

	require.NoError(t, os.MkdirAll(storeDir, 0o755))
	runGit(t, storeDir, "init")
	configureGit(t, storeDir, "Test", "test@binpass.dev")
	require.NoError(t, os.WriteFile(filepath.Join(storeDir, ".gitattributes"),
		[]byte("*.gpg binary\n*.age binary\n"), 0o644))
	runGit(t, storeDir, "add", ".gitattributes")
	runGit(t, storeDir, "commit", "-m", "init")
	runGit(t, storeDir, "remote", "add", "origin", bareDir)
	branch := gitBranch(t, storeDir)
	runGit(t, storeDir, "push", "-u", "origin", branch)

	g, err := NewGitRemote(GitOptions{Name: "origin", Dir: storeDir})
	require.NoError(t, err)
	defer func() { _ = g.Close() }()

	// Name and Lock.
	assert.Equal(t, "origin", g.Name())
	lock, err := g.Lock(ctx)
	require.NoError(t, err)
	require.NoError(t, lock.Unlock(ctx))

	// Put a file.
	rev, err := g.Put(ctx, "sites/example.gpg", bytes.NewReader([]byte("content")), "")
	require.NoError(t, err)
	assert.NotEmpty(t, rev)

	// Push to bare.
	require.NoError(t, g.Push(ctx))

	// Clone into a second store and verify the file is there.
	storeDir2 := filepath.Join(tmp, "store2")
	require.NoError(t, os.MkdirAll(storeDir2, 0o755))
	runGit(t, storeDir2, "clone", bareDir, ".")
	data, err := os.ReadFile(filepath.Join(storeDir2, "sites", "example.gpg"))
	require.NoError(t, err)
	assert.Equal(t, "content", string(data))

	// Make a change in the second store.
	g2, err := NewGitRemote(GitOptions{Name: "origin", Dir: storeDir2})
	require.NoError(t, err)
	defer func() { _ = g2.Close() }()

	_, err = g2.Put(ctx, "sites/example.gpg", bytes.NewReader([]byte("updated")), rev)
	require.NoError(t, err)
	require.NoError(t, g2.Push(ctx))

	// Pull in the first store should see the update.
	require.NoError(t, g.Pull(ctx))
	rc, newRev, err := g.Get(ctx, "sites/example.gpg")
	require.NoError(t, err)
	defer func() { _ = rc.Close() }()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(rc)
	assert.Equal(t, "updated", buf.String())
	assert.NotEqual(t, rev, newRev)
}

// TestGitRemote_DeleteAndRename tests Delete and Rename operations.
func TestGitRemote_DeleteAndRename(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping git integration test in short mode")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not found on PATH")
	}

	ctx := context.Background()
	storeDir, _ := setupGitRepo(t)

	g, err := NewGitRemote(GitOptions{Name: "origin", Dir: storeDir})
	require.NoError(t, err)
	defer func() { _ = g.Close() }()

	// Put two files.
	_, err = g.Put(ctx, "sites/a.gpg", bytes.NewReader([]byte("aaa")), "")
	require.NoError(t, err)
	_, err = g.Put(ctx, "sites/b.gpg", bytes.NewReader([]byte("bbb")), "")
	require.NoError(t, err)

	// Rename a → c.
	require.NoError(t, g.Rename(ctx, "sites/a.gpg", "sites/c.gpg"))

	files, err := g.List(ctx)
	require.NoError(t, err)
	paths := make(map[string]bool, len(files))
	for _, f := range files {
		paths[f.Path] = true
	}
	assert.True(t, paths["sites/c.gpg"], "renamed file should exist")
	assert.False(t, paths["sites/a.gpg"], "old name should not exist")

	// Delete b.
	require.NoError(t, g.Delete(ctx, "sites/b.gpg", ""))

	files, err = g.List(ctx)
	require.NoError(t, err)
	assert.Len(t, files, 1)
	assert.Equal(t, "sites/c.gpg", files[0].Path)
}

// TestRemoteFromConfig tests the factory function.
func TestRemoteFromConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping git integration test in short mode")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not found on PATH")
	}

	// Git type with a temp directory.
	tmp := t.TempDir()
	runGit(t, tmp, "init")
	configureGit(t, tmp, "Test", "test@binpass.dev")
	require.NoError(t, os.WriteFile(filepath.Join(tmp, ".gitattributes"),
		[]byte("*.gpg binary\n"), 0o644))
	runGit(t, tmp, "add", ".gitattributes")
	runGit(t, tmp, "commit", "-m", "init")

	r, err := FromConfig("git", map[string]string{
		"name": "test",
		"dir":  tmp,
	})
	require.NoError(t, err)
	require.NoError(t, r.Close())
	assert.Equal(t, "test", r.Name())

	// Unknown type.
	_, err = FromConfig("ftp", map[string]string{})
	assert.Error(t, err)
}
