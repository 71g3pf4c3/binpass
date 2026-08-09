package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFsckReportsUntrackedEntriesAsWarnings(t *testing.T) {
	app := newTestApp(t)
	app.set(t, "alice", "hunter2\n")

	// An entry written since the last sync is expected, not broken: fsck
	// says so and still exits successfully.
	err := app.runFsck()
	require.NoError(t, err)
	assert.Contains(t, app.out.String(), "WARNING: alice.age")
	assert.Contains(t, app.out.String(), "0 error(s), 1 warning(s)")
}

func TestFsckOnAnEmptyStore(t *testing.T) {
	app := newTestApp(t)

	require.NoError(t, app.runFsck())
	assert.Contains(t, app.out.String(), "Store is consistent")
}

func TestFsckReportsAStateDBInsideTheStore(t *testing.T) {
	app := newTestApp(t)
	// A state database kept inside the store would be encrypted, pushed, and
	// synced back over itself.
	stateDir := filepath.Join(app.dir, ".binpass-state")
	require.NoError(t, os.MkdirAll(stateDir, 0o700))
	t.Setenv("BINPASS_STATE_DIR", stateDir)

	err := app.runFsck()
	require.Error(t, err)
	assert.Contains(t, app.errOut.String(), "ERROR:")
}
