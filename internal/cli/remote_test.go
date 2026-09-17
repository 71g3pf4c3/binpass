package cli

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/71g3pf4c3/binpass/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRemoteAdd(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "config.yaml")
	t.Setenv("BINPASS_CONFIG", cfgPath)

	app := &App{
		Cfg: config.Default(),
		Out: os.Stdout,
		Err: os.Stderr,
	}

	err := app.runRemoteAdd("git", "origin", "git@github.com:you/store.git")
	require.NoError(t, err)

	// Verify the file was written.
	data, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), "origin")
	assert.Contains(t, string(data), "git")
	assert.Contains(t, string(data), "git@github.com:you/store.git")

	// Verify in-memory config.
	require.NotNil(t, app.Cfg.Remotes)
	rc, ok := app.Cfg.Remotes["origin"]
	require.True(t, ok)
	assert.Equal(t, "git", rc.Type)
	assert.Equal(t, "git@github.com:you/store.git", rc.URL)
}

func TestRemoteAddThenRemove(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "config.yaml")
	t.Setenv("BINPASS_CONFIG", cfgPath)

	app := &App{
		Cfg: config.Default(),
		Out: os.Stdout,
		Err: os.Stderr,
	}

	require.NoError(t, app.runRemoteAdd("s3", "backup", "mybucket:store"))
	require.NoError(t, app.runRemoteAdd("gdrive", "gdrive", "gdrive"))

	// Remove one.
	require.NoError(t, app.runRemoteRemove("backup"))

	// Verify only gdrive remains.
	require.NotNil(t, app.Cfg.Remotes)
	_, ok := app.Cfg.Remotes["backup"]
	assert.False(t, ok, "backup should be removed from in-memory config")
	_, ok = app.Cfg.Remotes["gdrive"]
	assert.True(t, ok, "gdrive should still be in in-memory config")

	// Verify the file.
	data, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "backup")
	assert.Contains(t, string(data), "gdrive")
}

func TestRemoteAddInvalidType(t *testing.T) {
	app := &App{
		Cfg: config.Default(),
		Out: os.Stdout,
		Err: os.Stderr,
	}

	err := app.runRemoteAdd("ftp", "bad")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown type")
}

func TestRemoteRemoveNotFound(t *testing.T) {
	app := &App{
		Cfg: config.Default(),
		Out: os.Stdout,
		Err: os.Stderr,
	}

	err := app.runRemoteRemove("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestRemoteAddPreservesExistingConfig(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "config.yaml")
	t.Setenv("BINPASS_CONFIG", cfgPath)

	// Write an existing config with a non-sync key.
	initial := "crypto:\n  default: age\nstore:\n  dir: /tmp/mystore\n"
	require.NoError(t, os.WriteFile(cfgPath, []byte(initial), 0o644))

	app := &App{
		Cfg: config.Default(),
		Out: os.Stdout,
		Err: os.Stderr,
	}

	require.NoError(t, app.runRemoteAdd("git", "origin", "git@github.com:you/store.git"))

	// Verify the file still contains the non-sync keys.
	data, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	content := string(data)
	assert.Contains(t, content, "default: age", "existing keys should be preserved")
	assert.Contains(t, content, "origin", "new remote should be added")
}

func TestRemoteList(t *testing.T) {
	app := &App{
		Cfg: config.Default(),
		Out: os.Stdout,
		Err: os.Stderr,
	}
	app.Cfg.Remotes = map[string]config.RemoteConfig{
		"origin": {Type: "git", URL: "git@github.com:you/store.git"},
		"backup": {Type: "s3", URL: "mybucket:store"},
	}

	// Should not error.
	err := app.runRemoteList()
	assert.NoError(t, err)
}

func TestRemoteListEmpty(t *testing.T) {
	app := &App{
		Cfg: config.Default(),
		Out: os.Stdout,
		Err: os.Stderr,
	}

	err := app.runRemoteList()
	assert.NoError(t, err)
}

func TestRemoteAddS3KeyValues(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "config.yaml")
	t.Setenv("BINPASS_CONFIG", cfgPath)

	app := &App{Cfg: config.Default(), Out: io.Discard, Err: io.Discard}

	// The native S3 transport takes the endpoint as the URL and the rest
	// as key=value pairs; credentials deliberately have no form at all.
	require.NoError(t, app.runRemoteAdd("s3", "backup",
		"https://s3.example.com", "bucket=my-bucket", "folder=password-store", "region=eu-west-1"))

	rc, ok := app.Cfg.Remotes["backup"]
	require.True(t, ok)
	assert.Equal(t, "https://s3.example.com", rc.URL)
	assert.Equal(t, "my-bucket", rc.Bucket)
	assert.Equal(t, "password-store", rc.Folder)
	assert.Equal(t, "eu-west-1", rc.Region)

	data, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), "bucket: my-bucket")
	assert.Contains(t, string(data), "region: eu-west-1")
}

func TestRemoteAddRejectsUnknownField(t *testing.T) {
	app := &App{Cfg: config.Default(), Out: io.Discard, Err: io.Discard}
	err := app.runRemoteAdd("s3", "backup", "https://s3.example.com", "password=nope")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown field")
}
