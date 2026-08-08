package storage_test

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/71g3pf4c3/binpass/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// exts are the crypto extensions the tests consider, gpg first.
var exts = []string{".gpg", ".age"}

// newFS returns an FS over a fresh temporary store.
func newFS(t *testing.T) *storage.FS {
	t.Helper()
	return storage.New(t.TempDir())
}

// touch creates a file with the given content, making parents as needed.
func touch(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}

func TestPath(t *testing.T) {
	f := newFS(t)
	got, err := f.Path("github.com/alice", ".gpg")
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(f.Dir, "github.com", "alice.gpg"), got)
}

func TestPathRejectsTraversal(t *testing.T) {
	f := newFS(t)
	for _, name := range []string{"../escape", "a/../../escape", "..", "a/b/../../.."} {
		_, err := f.Path(name, ".gpg")
		assert.ErrorIs(t, err, storage.ErrOutsideStore, "name %q must be refused", name)
	}
}

func TestPathTreatsLeadingSlashAsStoreRelative(t *testing.T) {
	// pass resolves "$PREFIX/$name.gpg", so a leading slash names an entry
	// inside the store rather than an absolute path.
	f := newFS(t)
	got, err := f.Path("/etc/passwd", ".gpg")
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(f.Dir, "etc", "passwd.gpg"), got)
}

func TestPathAllowsInternalDotDot(t *testing.T) {
	f := newFS(t)
	got, err := f.Path("a/b/../c", ".gpg")
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(f.Dir, "a", "c.gpg"), got)
}

func TestName(t *testing.T) {
	f := newFS(t)
	got, err := f.Name(filepath.Join(f.Dir, "github.com", "alice.gpg"))
	require.NoError(t, err)
	assert.Equal(t, "github.com/alice", got)

	_, err = f.Name("/elsewhere/x.gpg")
	assert.ErrorIs(t, err, storage.ErrOutsideStore)
}

func TestFindPrefersExtensionOrder(t *testing.T) {
	f := newFS(t)
	touch(t, filepath.Join(f.Dir, "both.gpg"), "g")
	touch(t, filepath.Join(f.Dir, "both.age"), "a")
	touch(t, filepath.Join(f.Dir, "only.age"), "a")

	got, err := f.Find("both", exts)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(f.Dir, "both.gpg"), got)

	got, err = f.Find("both", []string{".age", ".gpg"})
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(f.Dir, "both.age"), got, "the caller's preference order decides")

	got, err = f.Find("only", exts)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(f.Dir, "only.age"), got)
}

func TestFindMissing(t *testing.T) {
	_, err := newFS(t).Find("nope", exts)
	assert.ErrorIs(t, err, fs.ErrNotExist)
}

func TestListSortedAndFiltered(t *testing.T) {
	f := newFS(t)
	touch(t, filepath.Join(f.Dir, "b.gpg"), "x")
	touch(t, filepath.Join(f.Dir, "a.age"), "x")
	touch(t, filepath.Join(f.Dir, "sub", "c.gpg"), "x")
	touch(t, filepath.Join(f.Dir, "notes.txt"), "x")
	touch(t, filepath.Join(f.Dir, ".gpg-id"), "x")
	touch(t, filepath.Join(f.Dir, ".git", "config.gpg"), "x")

	entries, err := f.Entries("", exts)
	require.NoError(t, err)

	var names []string
	for _, e := range entries {
		names = append(names, e.Name)
	}
	assert.Equal(t, []string{"a", "b", "sub/c"}, names,
		"dotfiles, dot-directories and unknown extensions stay out of listings")
}

func TestListSubtree(t *testing.T) {
	f := newFS(t)
	touch(t, filepath.Join(f.Dir, "top.gpg"), "x")
	touch(t, filepath.Join(f.Dir, "sub", "c.gpg"), "x")

	entries, err := f.Entries("sub", exts)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "sub/c", entries[0].Name)
	assert.Equal(t, ".gpg", entries[0].Ext)
}

func TestIsDir(t *testing.T) {
	f := newFS(t)
	touch(t, filepath.Join(f.Dir, "sub", "c.gpg"), "x")
	assert.True(t, f.IsDir("sub"))
	assert.False(t, f.IsDir("sub/c"))
	assert.False(t, f.IsDir("missing"))
}

func TestWriteIsAtomicAndLeavesNoTemporaries(t *testing.T) {
	f := newFS(t)
	path := filepath.Join(f.Dir, "deep", "entry.age")
	require.NoError(t, f.Write(path, []byte("ciphertext")))

	got, err := f.Read(path)
	require.NoError(t, err)
	assert.Equal(t, "ciphertext", string(got))

	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	require.Len(t, entries, 1, "no temporary file is left behind")
}

func TestWriteFromFailureLeavesTargetUntouched(t *testing.T) {
	f := newFS(t)
	path := filepath.Join(f.Dir, "entry.age")
	require.NoError(t, f.Write(path, []byte("original")))

	err := f.WriteFrom(path, func(io.Writer) error { return assert.AnError })
	require.ErrorIs(t, err, assert.AnError)

	got, err := f.Read(path)
	require.NoError(t, err)
	assert.Equal(t, "original", string(got), "a failed write must not damage the existing secret")

	entries, err := os.ReadDir(f.Dir)
	require.NoError(t, err)
	assert.Len(t, entries, 1, "the temporary is cleaned up on failure")
}

func TestWriteHonoursUmask(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	f := newFS(t)
	path := filepath.Join(f.Dir, "sub", "entry.age")
	require.NoError(t, f.Write(path, []byte("x")))

	st, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), st.Mode().Perm(), "secrets are never group- or world-readable")

	dst, err := os.Stat(filepath.Dir(path))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), dst.Mode().Perm())
}

func TestRemovePrunesEmptyDirectories(t *testing.T) {
	f := newFS(t)
	path := filepath.Join(f.Dir, "a", "b", "entry.gpg")
	require.NoError(t, f.Write(path, []byte("x")))
	require.NoError(t, f.Remove(path))

	_, err := os.Stat(filepath.Join(f.Dir, "a"))
	assert.True(t, os.IsNotExist(err), "directories emptied by a removal are pruned")

	_, err = os.Stat(f.Dir)
	assert.NoError(t, err, "the store root itself is never pruned")
}

func TestRemoveKeepsNonEmptyDirectories(t *testing.T) {
	f := newFS(t)
	require.NoError(t, f.Write(filepath.Join(f.Dir, "a", "one.gpg"), []byte("x")))
	require.NoError(t, f.Write(filepath.Join(f.Dir, "a", "two.gpg"), []byte("x")))
	require.NoError(t, f.Remove(filepath.Join(f.Dir, "a", "one.gpg")))

	_, err := os.Stat(filepath.Join(f.Dir, "a", "two.gpg"))
	assert.NoError(t, err)
}

func TestRename(t *testing.T) {
	f := newFS(t)
	from := filepath.Join(f.Dir, "old", "entry.gpg")
	to := filepath.Join(f.Dir, "new", "entry.gpg")
	require.NoError(t, f.Write(from, []byte("x")))
	require.NoError(t, f.Rename(from, to))

	_, err := os.Stat(to)
	assert.NoError(t, err)
	_, err = os.Stat(filepath.Join(f.Dir, "old"))
	assert.True(t, os.IsNotExist(err), "the source directory is pruned when it empties")
}
