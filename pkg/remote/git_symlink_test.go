package remote

import (
	"context"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGitRemote_RejectsSymlinkedStoreContent commits a symlink into the store,
// which is what whoever can push to the remote is able to do, and checks that
// the sync side refuses the tree instead of dereferencing the link: the walk
// in ensurePrivate chmods what it finds, and List hashes it.
func TestGitRemote_RejectsSymlinkedStoreContent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping git integration test in short mode")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not found on PATH")
	}

	tests := []struct {
		name string
		// link is the name the hostile commit uses inside the store.
		link string
		// toDir points the link at a directory instead of a file.
		toDir bool
	}{
		{name: "entry", link: "alice.gpg"},
		{name: "recipients file", link: ".gpg-id"},
		{name: "directory", link: "mail", toDir: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			outside := t.TempDir()
			require.NoError(t, os.Chmod(outside, 0o755))
			loot := filepath.Join(outside, "loot")
			require.NoError(t, os.WriteFile(loot, []byte("a local file"), 0o644))

			storeDir, _ := setupGitRepo(t)
			g, err := NewGitRemote(GitOptions{Name: "origin", Dir: storeDir})
			require.NoError(t, err)
			defer func() { _ = g.Close() }()

			target, wantPerm := loot, fs.FileMode(0o644)
			if tc.toDir {
				target, wantPerm = outside, fs.FileMode(0o755)
			}
			require.NoError(t, os.Symlink(target, filepath.Join(storeDir, tc.link)))
			runGit(t, storeDir, "add", "-A")
			runGit(t, storeDir, "commit", "-m", "hostile symlink")

			_, err = g.List(ctx)
			assert.ErrorIs(t, err, ErrSymlink, "a symlink in store content must abort the sync")

			st, err := os.Lstat(target)
			require.NoError(t, err)
			assert.Equal(t, wantPerm, st.Mode().Perm(),
				"the link target keeps its own permissions")
			got, err := os.ReadFile(loot)
			require.NoError(t, err)
			assert.Equal(t, "a local file", string(got))
		})
	}
}

// TestGitRemote_AllowsSymlinkedStoreRoot keeps the common pass setup working:
// the store itself lives elsewhere and is symlinked into place.
func TestGitRemote_AllowsSymlinkedStoreRoot(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping git integration test in short mode")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not found on PATH")
	}

	ctx := context.Background()
	storeDir, _ := setupGitRepo(t)
	link := filepath.Join(t.TempDir(), "password-store")
	require.NoError(t, os.Symlink(storeDir, link))

	g, err := NewGitRemote(GitOptions{Name: "origin", Dir: link})
	require.NoError(t, err)
	defer func() { _ = g.Close() }()

	require.NoError(t, os.WriteFile(filepath.Join(storeDir, "alice.gpg"), []byte("ciphertext"), 0o600))
	runGit(t, storeDir, "add", "-A")
	runGit(t, storeDir, "commit", "-m", "add alice")

	files, err := g.List(ctx)
	require.NoError(t, err)
	require.Len(t, files, 1)
	assert.Equal(t, "alice.gpg", files[0].Path)
}
