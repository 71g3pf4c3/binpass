package cli

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/71g3pf4c3/binpass/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSyncHistory_Git(t *testing.T) {
	app := newTestApp(t)
	app.Cfg.Remotes = map[string]config.RemoteConfig{"origin": {Type: "git", URL: bareRepo(t)}}
	app.set(t, "github.com/alice", "hunter2\n")
	require.NoError(t, exec.Command("git", "-C", app.dir, "init", "-q").Run()) //nolint:gosec // fixed arguments.
	gitIdentity(t, app.dir)
	require.NoError(t, app.runSync(context.Background(), "origin", false))

	app.out.Reset()
	require.NoError(t, app.runSyncHistory(context.Background(), "origin"))

	lines := strings.Split(strings.TrimSpace(app.out.String()), "\n")
	require.NotEmpty(t, lines, "a synced git remote has commits to show")
	assert.Regexp(t, `^[0-9a-f]{7} `, lines[0], "git history comes in --oneline form")
}

// TestSyncHistoryAndRestore_Restic drives the snapshot round trip against the
// real restic binary: sync creates a snapshot, history lists it, an edit lands
// after it, restore reverts the edit. Skipped without restic on PATH, the
// same way the golden suite skips without pass.
func TestSyncHistoryAndRestore_Restic(t *testing.T) {
	if _, err := exec.LookPath("restic"); err != nil {
		t.Skip("restic not on PATH")
	}
	app := newTestApp(t)
	repo := filepath.Join(t.TempDir(), "repo")
	app.Cfg.Remotes = map[string]config.RemoteConfig{
		"backup": {Type: "restic", URL: repo, Password: "test"},
	}
	app.set(t, "bank/tinkoff", "old-password\n")
	require.NoError(t, app.runSync(context.Background(), "backup", false))

	// History lists the snapshot that sync created.
	app.out.Reset()
	require.NoError(t, app.runSyncHistory(context.Background(), "backup"))
	firstLine := strings.SplitN(strings.TrimSpace(app.out.String()), "\n", 2)[0]
	snapID := strings.Fields(firstLine)[0]
	require.NotEmpty(t, snapID, "the snapshot listing starts with a restorable ID")

	// An edit after the snapshot is what restore exists to undo.
	app.set(t, "bank/tinkoff", "new-password\n")

	app.In = strings.NewReader("y\n")
	require.NoError(t, app.runSyncRestore(context.Background(), snapID, "backup"))

	s, err := app.Store()
	require.NoError(t, err)
	sec, err := s.Get("bank/tinkoff")
	require.NoError(t, err)
	assert.Equal(t, "old-password", sec.Password(), "restore puts the snapshot's version back")
}

func TestSyncRestore_DeclinedPromptKeepsStore(t *testing.T) {
	app := newTestApp(t)
	repo := filepath.Join(t.TempDir(), "repo")
	app.Cfg.Remotes = map[string]config.RemoteConfig{
		"backup": {Type: "restic", URL: repo, Password: "test"},
	}
	app.set(t, "bank/tinkoff", "old-password\n")
	if _, err := exec.LookPath("restic"); err != nil {
		t.Skip("restic not on PATH")
	}
	require.NoError(t, app.runSync(context.Background(), "backup", false))
	app.set(t, "bank/tinkoff", "new-password\n")

	app.In = strings.NewReader("n\n")
	require.NoError(t, app.runSyncRestore(context.Background(), "anything", "backup"))

	s, err := app.Store()
	require.NoError(t, err)
	sec, err := s.Get("bank/tinkoff")
	require.NoError(t, err)
	assert.Equal(t, "new-password", sec.Password(), "a declined restore must not touch the store")
}
