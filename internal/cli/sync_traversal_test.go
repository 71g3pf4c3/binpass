package cli

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/71g3pf4c3/binpass/pkg/remote"
	"github.com/71g3pf4c3/binpass/pkg/sync"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPullRefusesToWriteOutsideTheStore covers the case where the other side
// of a sync is hostile. Paths in a remote listing are chosen by whoever
// controls the remote, and joining one onto the store root without checking it
// first let a pull drop a file anywhere the user could write.
func TestPullRefusesToWriteOutsideTheStore(t *testing.T) {
	app := newTestApp(t)
	s, err := app.Store()
	require.NoError(t, err)
	ctx := context.Background()

	// The target sits next to the store, so a successful escape is visible
	// without writing anywhere that matters.
	outside := filepath.Join(filepath.Dir(app.dir), "escaped.age")
	evil := "../escaped.age"

	mem := remote.NewMemRemote(remote.MemOptions{Name: "mem"})
	_, err = mem.Put(ctx, evil, strings.NewReader("payload"), "")
	require.NoError(t, err)

	db, err := sync.OpenStateDB(t.TempDir())
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	acts := []sync.Action{{
		Kind:   sync.ActionPull,
		Path:   evil,
		Remote: &sync.FileState{Path: evil, Size: 7, Version: sync.VersionVector{"dev2": 1}, Device: "dev2"},
	}}
	err = app.applyActions(ctx, s, mem, db, sync.Snapshot{}, acts, "dev1")

	require.ErrorIs(t, err, remote.ErrUnsafePath, "the escaping path must be refused")
	assert.NoFileExists(t, outside, "nothing may be written outside the store")
}

// TestPullRefusesAnAbsoluteRemotePath is the same attack spelled with an
// absolute path rather than a relative one.
func TestPullRefusesAnAbsoluteRemotePath(t *testing.T) {
	app := newTestApp(t)
	s, err := app.Store()
	require.NoError(t, err)
	ctx := context.Background()

	target := filepath.Join(t.TempDir(), "absolute.age")
	mem := remote.NewMemRemote(remote.MemOptions{Name: "mem"})
	_, err = mem.Put(ctx, target, strings.NewReader("payload"), "")
	require.NoError(t, err)

	db, err := sync.OpenStateDB(t.TempDir())
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	acts := []sync.Action{{
		Kind:   sync.ActionPull,
		Path:   target,
		Remote: &sync.FileState{Path: target, Size: 7, Version: sync.VersionVector{"dev2": 1}, Device: "dev2"},
	}}
	err = app.applyActions(ctx, s, mem, db, sync.Snapshot{}, acts, "dev1")

	require.ErrorIs(t, err, remote.ErrUnsafePath)
	assert.NoFileExists(t, target)
}

// TestGitListRejectsAnEscapingPath checks the transport boundary itself: a
// repository that tracks a file outside the store must not be reported as a
// list of entries to pull.
func TestGitListRejectsAnEscapingPath(t *testing.T) {
	// os.Root-style protection belongs at the boundary, so verify the helper
	// the transports call rather than standing up a hostile repository.
	assert.ErrorIs(t, remote.CheckPath("../../outside.age"), remote.ErrUnsafePath)
	assert.NoError(t, remote.CheckPath("sites/alice.age"))
}
