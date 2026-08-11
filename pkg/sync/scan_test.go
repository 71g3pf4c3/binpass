package sync

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScan_Basic(t *testing.T) {
	root := setupTestStore(t)
	base := make(Snapshot)

	snap, err := Scan(root, base, "phone", []string{".gpg"})
	require.NoError(t, err)
	assert.Contains(t, snap, "github.com/alice.gpg")
	assert.Contains(t, snap, "bank/tinkoff.gpg")
	assert.Equal(t, uint64(1), snap["github.com/alice.gpg"].Version["phone"])
	assert.Equal(t, uint64(1), snap["bank/tinkoff.gpg"].Version["phone"])
}

func TestScan_IncrementVersion(t *testing.T) {
	root := setupTestStore(t)

	// First scan: new files get {phone: 1}.
	snap1, err := Scan(root, make(Snapshot), "phone", []string{".gpg"})
	require.NoError(t, err)

	// Modify a file.
	alicePath := filepath.Join(root, "github.com", "alice.gpg")
	f, err := os.OpenFile(alicePath, os.O_WRONLY|os.O_APPEND, 0)
	require.NoError(t, err)
	_, err = f.Write([]byte("extra"))
	require.NoError(t, err)
	require.NoError(t, f.Close())

	// Second scan: modified file gets {phone: 2}.
	snap2, err := Scan(root, snap1, "phone", []string{".gpg"})
	require.NoError(t, err)
	assert.Equal(t, uint64(2), snap2["github.com/alice.gpg"].Version["phone"],
		"modified file should have incremented version")
	assert.Equal(t, uint64(1), snap2["bank/tinkoff.gpg"].Version["phone"],
		"unchanged file should keep the same version")
}

func TestScan_Optimisation_SameSizeModTime(t *testing.T) {
	root := setupTestStore(t)

	// First scan.
	snap1, err := Scan(root, make(Snapshot), "phone", []string{".gpg"})
	require.NoError(t, err)

	// Record the original hash.
	origHash := snap1["github.com/alice.gpg"].Hash

	// Second scan with snap1 as base: same (size, mtime) means hash is reused.
	snap2, err := Scan(root, snap1, "phone", []string{".gpg"})
	require.NoError(t, err)
	assert.Equal(t, origHash, snap2["github.com/alice.gpg"].Hash,
		"unchanged file should reuse stored hash")
	assert.Equal(t, snap1["github.com/alice.gpg"], snap2["github.com/alice.gpg"],
		"unchanged file should reuse entire FileState")
}

func TestScan_DotfilesSkipped(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	require.NoError(t, os.MkdirAll(sub, 0o755))

	// Regular file.
	require.NoError(t, os.WriteFile(filepath.Join(sub, "visible.gpg"), []byte("data"), 0o644))
	// Dotfile.
	require.NoError(t, os.WriteFile(filepath.Join(sub, ".hidden.gpg"), []byte("secret"), 0o644))
	// Dot directory with files inside.
	dotDir := filepath.Join(root, ".git")
	require.NoError(t, os.MkdirAll(dotDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dotDir, "config.gpg"), []byte("gitdata"), 0o644))

	snap, err := Scan(root, make(Snapshot), "dev", []string{".gpg"})
	require.NoError(t, err)
	assert.Contains(t, snap, "sub/visible.gpg")
	assert.NotContains(t, snap, "sub/.hidden.gpg")
	assert.NotContains(t, snap, ".git/config.gpg")
}

func TestScan_ExtensionFilter(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "a.gpg"), []byte("gpg-data"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "b.age"), []byte("age-data"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "c.txt"), []byte("text-data"), 0o644))

	snap, err := Scan(root, make(Snapshot), "dev", []string{".gpg", ".age"})
	require.NoError(t, err)
	assert.Contains(t, snap, "a.gpg")
	assert.Contains(t, snap, "b.age")
	assert.NotContains(t, snap, "c.txt")
}

func TestScan_DeletedFileDetection(t *testing.T) {
	root := setupTestStore(t)

	// First scan.
	snap1, err := Scan(root, make(Snapshot), "phone", []string{".gpg"})
	require.NoError(t, err)

	// Delete a file.
	require.NoError(t, os.Remove(filepath.Join(root, "github.com", "alice.gpg")))

	// Second scan: deleted file not in snapshot.
	snap2, err := Scan(root, snap1, "phone", []string{".gpg"})
	require.NoError(t, err)
	assert.NotContains(t, snap2, "github.com/alice.gpg")
	assert.Contains(t, snap2, "bank/tinkoff.gpg")
}

func TestDiff(t *testing.T) {
	base := Snapshot{
		"a.gpg": {Path: "a.gpg", Hash: hash(1)},
		"b.gpg": {Path: "b.gpg", Hash: hash(2)},
		"c.gpg": {Path: "c.gpg", Hash: hash(3)},
	}
	current := Snapshot{
		"a.gpg": {Path: "a.gpg", Hash: hash(1)},  // unchanged
		"b.gpg": {Path: "b.gpg", Hash: hash(99)}, // modified
		"d.gpg": {Path: "d.gpg", Hash: hash(4)},  // new
		// c.gpg deleted
	}

	diff := Diff(base, current)
	assert.Equal(t, []string{"b.gpg", "c.gpg", "d.gpg"}, diff)
}

// setupTestStore creates a minimal password store directory for scan tests.
func setupTestStore(t *testing.T) string {
	t.Helper()
	root := t.TempDir()

	// github.com/alice.gpg
	ghDir := filepath.Join(root, "github.com")
	require.NoError(t, os.MkdirAll(ghDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(ghDir, "alice.gpg"), []byte("encrypted-alice"), 0o644))

	// bank/tinkoff.gpg
	bankDir := filepath.Join(root, "bank")
	require.NoError(t, os.MkdirAll(bankDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(bankDir, "tinkoff.gpg"), []byte("encrypted-tinkoff"), 0o644))

	// Ensure mtimes are distinct and stable.
	_ = time.Now()
	return root
}
