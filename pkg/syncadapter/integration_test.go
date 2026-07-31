package syncadapter_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/71g3pf4c3/binpass/pkg/crypto"
	"github.com/71g3pf4c3/binpass/pkg/remote/fsremote"
	binpasssync "github.com/71g3pf4c3/binpass/pkg/sync"
	"github.com/71g3pf4c3/binpass/pkg/syncadapter"
	"github.com/71g3pf4c3/binpass/pkg/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// client bundles a store, its adapter, and a device ID for a test peer.
type client struct {
	st      *store.Store
	adapter *syncadapter.Adapter
	engine  *binpasssync.Engine
}

// newClient creates a store sharing the given identity/recipient and wires a
// sync engine for it.
func newClient(t *testing.T, dir, deviceID string, id *age.X25519Identity) *client {
	t.Helper()
	c := crypto.NewAge([]age.Identity{id})
	st := store.New(dir, c)
	require.NoError(t, st.Init([]string{id.Recipient().String()}))
	adapter, err := syncadapter.New(st, deviceID)
	require.NoError(t, err)
	return &client{st: st, adapter: adapter, engine: binpasssync.NewEngine(adapter, adapter)}
}

// sync runs one synchronisation cycle against the shared remote path.
func (c *client) sync(t *testing.T, remotePath string) *binpasssync.Report {
	t.Helper()
	rem, err := fsremote.New(remotePath)
	require.NoError(t, err)
	defer rem.Close()
	rep, err := c.engine.Sync(context.Background(), rem)
	require.NoError(t, err)
	return rep
}

func TestTwoClientSync(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	root := t.TempDir()
	remotePath := filepath.Join(root, "remote")
	a := newClient(t, filepath.Join(root, "a"), "devA", id)
	b := newClient(t, filepath.Join(root, "b"), "devB", id)

	// A creates two secrets and pushes.
	require.NoError(t, a.st.SetRaw("github.com/alice", []byte("hunterA\n")))
	require.NoError(t, a.st.SetRaw("work/vpn", []byte("vpnpass\n")))
	repA := a.sync(t, remotePath)
	assert.Equal(t, 2, repA.Pushed)

	// B pulls both.
	repB := b.sync(t, remotePath)
	assert.Equal(t, 2, repB.Pulled)

	names, err := b.st.List()
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"github.com/alice", "work/vpn"}, names)

	got, err := b.st.GetRaw("github.com/alice")
	require.NoError(t, err)
	assert.Equal(t, "hunterA\n", string(got))
}

func TestConcurrentEditConflict(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	root := t.TempDir()
	remotePath := filepath.Join(root, "remote")
	a := newClient(t, filepath.Join(root, "a"), "devA", id)
	b := newClient(t, filepath.Join(root, "b"), "devB", id)

	// Establish a shared baseline.
	require.NoError(t, a.st.SetRaw("shared", []byte("v0\n")))
	a.sync(t, remotePath)
	b.sync(t, remotePath)

	// Both edit the same entry offline.
	require.NoError(t, a.st.SetRaw("shared", []byte("vA\n")))
	require.NoError(t, b.st.SetRaw("shared", []byte("vB\n")))

	// A syncs first (wins the canonical path).
	a.sync(t, remotePath)
	// B syncs and must observe a conflict, keeping its local copy as sibling.
	repB := b.sync(t, remotePath)
	require.Len(t, repB.Conflicts, 1)
	assert.Equal(t, binpasssync.ConflictConcurrentEdit, repB.Conflicts[0].Kind)

	names, err := b.st.List()
	require.NoError(t, err)

	// Canonical path holds A's value; a sibling holds B's value.
	shared, err := b.st.GetRaw("shared")
	require.NoError(t, err)
	assert.Equal(t, "vA\n", string(shared))

	var sibling string
	for _, n := range names {
		if strings.HasPrefix(n, "shared.conflict-") {
			sibling = n
		}
	}
	require.NotEmpty(t, sibling, "expected a conflict sibling")
	sib, err := b.st.GetRaw(sibling)
	require.NoError(t, err)
	assert.Equal(t, "vB\n", string(sib))
}

func TestDeletePropagates(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	root := t.TempDir()
	remotePath := filepath.Join(root, "remote")
	a := newClient(t, filepath.Join(root, "a"), "devA", id)
	b := newClient(t, filepath.Join(root, "b"), "devB", id)

	require.NoError(t, a.st.SetRaw("temp", []byte("x\n")))
	a.sync(t, remotePath)
	b.sync(t, remotePath)
	require.True(t, b.st.Exists("temp"))

	// A deletes and syncs; B should see the deletion.
	require.NoError(t, a.st.Remove("temp"))
	a.sync(t, remotePath)
	b.sync(t, remotePath)
	assert.False(t, b.st.Exists("temp"))
}
