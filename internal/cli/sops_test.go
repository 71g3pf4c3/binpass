package cli

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/71g3pf4c3/binpass/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sopsWorkspace builds an isolated sops project with its own age key and
// .sops.yaml, keeping the developer's real keys out of the test.
func sopsWorkspace(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("sops"); err != nil {
		t.Skip("sops not on PATH")
	}
	dir := t.TempDir()
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	keyFile := filepath.Join(dir, "key.txt")
	require.NoError(t, os.WriteFile(keyFile, []byte(id.String()+"\n"), 0o600))
	cfg := fmt.Sprintf("creation_rules:\n  - age: %s\n", id.Recipient())
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".sops.yaml"), []byte(cfg), 0o600))
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "cfg"))
	t.Setenv("SOPS_AGE_KEY_FILE", keyFile)
	t.Chdir(dir)
	return dir
}

// runSops executes `binpass sops ARGS...` with stdin and returns stdout.
func runSops(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	out := &bytes.Buffer{}
	app := &App{Cfg: config.Default(), Out: out, Err: &bytes.Buffer{}, In: strings.NewReader(stdin)}
	cmd := newSopsCmd(app)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestSops_RoundTrip(t *testing.T) {
	sopsWorkspace(t)

	_, err := runSops(t, "hunter2\n", "set", "secrets.yaml", "db/password")
	require.NoError(t, err)
	_, err = runSops(t, "-----BEGIN KEY-----\nabc\n-----END KEY-----\n", "set", "secrets.yaml", "ssh/id")
	require.NoError(t, err)
	_, err = runSops(t, "tok", "set", "secrets.yaml", "token")
	require.NoError(t, err)

	out, err := runSops(t, "", "ls", "secrets.yaml")
	require.NoError(t, err)
	assert.Equal(t, "db/password\nssh/id\ntoken\n", out)
	out, err = runSops(t, "", "ls", "secrets.yaml", "db")
	require.NoError(t, err)
	assert.Equal(t, "db/password\n", out)

	out, err = runSops(t, "", "get", "secrets.yaml", "db/password")
	require.NoError(t, err)
	assert.Equal(t, "hunter2", out, "single-line value loses its terminator")
	out, err = runSops(t, "", "get", "secrets.yaml", "ssh/id")
	require.NoError(t, err)
	assert.Equal(t, "-----BEGIN KEY-----\nabc\n-----END KEY-----\n", out, "multi-line value is verbatim")

	_, err = runSops(t, "", "get", "secrets.yaml", "nope")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nope is not in secrets.yaml")

	_, err = runSops(t, "", "rm", "secrets.yaml", "db")
	require.Error(t, err, "a group needs --recursive")
	_, err = runSops(t, "", "rm", "-r", "secrets.yaml", "db")
	require.NoError(t, err)
	_, err = runSops(t, "", "rm", "secrets.yaml", "token")
	require.NoError(t, err)
	out, err = runSops(t, "", "ls", "secrets.yaml")
	require.NoError(t, err)
	assert.Equal(t, "ssh/id\n", out)

	// The file is sops's own: its metadata survives every edit.
	raw, err := os.ReadFile("secrets.yaml")
	require.NoError(t, err)
	assert.Contains(t, string(raw), "sops:")
	assert.Contains(t, string(raw), "ENC[")
	assert.NotContains(t, string(raw), "BEGIN KEY")
}

func TestSops_UnsupportedExtension(t *testing.T) {
	sopsWorkspace(t)
	_, err := runSops(t, "", "ls", "secrets.env")
	require.Error(t, err)
	assert.Contains(t, err.Error(), ".yaml, .yml or .json")
}
