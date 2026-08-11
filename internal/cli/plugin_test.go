package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/71g3pf4c3/binpass/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubPlugin writes an executable plugin onto a PATH that contains nothing
// else, and returns the app and root command wired to it.
func stubPlugin(t *testing.T, name, script string) (*App, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the shebang convention is POSIX-only")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(script), 0o700)) //nolint:gosec // a test stub.
	t.Setenv("PATH", dir)

	// Keep discovery away from any real plugin directory belonging to the
	// developer running the tests.
	t.Setenv("BINPASS_DATA_DIR", filepath.Join(dir, "data"))

	cfg := config.Default()
	cfg.Dir = filepath.Join(dir, "store")
	app := NewApp(cfg)
	out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	app.Out, app.Err = out, errOut
	return app, out, errOut
}

func TestDispatchRunsAPlugin(t *testing.T) {
	app, out, _ := stubPlugin(t, "binpass-greet", "#!/bin/sh\necho \"greeting $*\"\n")
	root := newRootCmd(app, "test", "none", "none")

	handled, err := app.dispatchPlugin(context.Background(), root, []string{"greet", "world"})
	require.True(t, handled)
	require.NoError(t, err)
	assert.Equal(t, "greeting world\n", out.String())
}

// TestDispatchPassesFlagsThrough is the reason dispatch happens before cobra
// parses anything: cobra owns --flag and would reject it as unknown long
// before the plugin could be handed it.
func TestDispatchPassesFlagsThrough(t *testing.T) {
	app, out, _ := stubPlugin(t, "binpass-greet", "#!/bin/sh\necho \"args: $*\"\n")
	root := newRootCmd(app, "test", "none", "none")

	handled, err := app.dispatchPlugin(context.Background(), root, []string{"greet", "--loud", "-n", "2"})
	require.True(t, handled)
	require.NoError(t, err)
	assert.Equal(t, "args: --loud -n 2\n", out.String())
}

// TestBuiltinsWinOverPlugins pins the safety rule: a plugin must not be able
// to replace the commands that handle secrets, however it is named.
func TestBuiltinsWinOverPlugins(t *testing.T) {
	app, out, _ := stubPlugin(t, "binpass-show", "#!/bin/sh\necho hijacked\n")
	root := newRootCmd(app, "test", "none", "none")

	handled, err := app.dispatchPlugin(context.Background(), root, []string{"show", "entry"})
	assert.False(t, handled, "the builtin show must keep the name")
	assert.NoError(t, err)
	assert.Empty(t, out.String())
}

// TestAliasesWinOverPlugins covers the same rule for the alternative spelling
// of a builtin, which is just as much a real command.
func TestAliasesWinOverPlugins(t *testing.T) {
	app, _, _ := stubPlugin(t, "binpass-list", "#!/bin/sh\necho hijacked\n")
	root := newRootCmd(app, "test", "none", "none")

	handled, _ := app.dispatchPlugin(context.Background(), root, []string{"list"})
	assert.False(t, handled, "list is an alias of ls and cannot be taken over")
}

func TestDispatchIgnoresUnknownCommands(t *testing.T) {
	app, _, _ := stubPlugin(t, "binpass-greet", "#!/bin/sh\nexit 0\n")
	root := newRootCmd(app, "test", "none", "none")

	handled, err := app.dispatchPlugin(context.Background(), root, []string{"nosuchthing"})
	assert.False(t, handled, "an unclaimed name must fall through to show")
	assert.NoError(t, err)
}

// TestDispatchIgnoresLeadingFlags keeps `binpass --help` from being treated
// as a plugin lookup.
func TestDispatchIgnoresLeadingFlags(t *testing.T) {
	app, _, _ := stubPlugin(t, "binpass-greet", "#!/bin/sh\nexit 0\n")
	root := newRootCmd(app, "test", "none", "none")

	handled, _ := app.dispatchPlugin(context.Background(), root, []string{"--help"})
	assert.False(t, handled)
}

// TestPluginExitCodeSurvives matters for scripting: a wrapper around
// `binpass foo` can only branch on failure if the plugin's status is what
// binpass returns.
func TestPluginExitCodeSurvives(t *testing.T) {
	app, _, _ := stubPlugin(t, "binpass-fail", "#!/bin/sh\nexit 42\n")
	root := newRootCmd(app, "test", "none", "none")

	handled, err := app.dispatchPlugin(context.Background(), root, []string{"fail"})
	require.True(t, handled)
	require.Error(t, err)

	var exit *exitError
	require.ErrorAs(t, err, &exit)
	assert.Equal(t, 42, exit.code)
}

// TestPluginEnvironmentContract checks the variables a plugin is promised,
// since they are the whole interface a plugin author codes against.
func TestPluginEnvironmentContract(t *testing.T) {
	script := "#!/bin/sh\n" +
		"echo \"api=$BINPASS_API\"\n" +
		"echo \"bin=$BINPASS_BIN\"\n" +
		"echo \"store=$BINPASS_STORE\"\n" +
		"echo \"version=$BINPASS_VERSION\"\n" +
		"echo \"passdir=$PASSWORD_STORE_DIR\"\n"
	app, out, _ := stubPlugin(t, "binpass-env", script)
	app.Version = "1.2.3"
	root := newRootCmd(app, "1.2.3", "none", "none")

	handled, err := app.dispatchPlugin(context.Background(), root, []string{"env"})
	require.True(t, handled)
	require.NoError(t, err)

	got := out.String()
	assert.Contains(t, got, "api=1")
	assert.Contains(t, got, "version=1.2.3")
	assert.Contains(t, got, "store="+app.Cfg.Dir)
	// Scripts written for pass reach for this name, and must find the same
	// store binpass is using.
	assert.Contains(t, got, "passdir="+app.Cfg.Dir)
	// The callback path must be absolute: a plugin cannot be expected to
	// find binpass on a PATH it does not control.
	for _, line := range strings.Split(got, "\n") {
		if bin, ok := strings.CutPrefix(line, "bin="); ok {
			assert.True(t, filepath.IsAbs(bin), "BINPASS_BIN must be absolute, got %q", bin)
		}
	}
}

func TestPluginListReportsUnusablePlugins(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the executable bit is POSIX-only")
	}
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "binpass-good"), []byte("#!/bin/sh\n"), 0o700)) //nolint:gosec // a test stub.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "binpass-broken"), []byte("#!/bin/sh\n"), 0o600))
	t.Setenv("PATH", dir)
	t.Setenv("BINPASS_DATA_DIR", filepath.Join(dir, "data"))

	cfg := config.Default()
	app := NewApp(cfg)
	out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	app.Out, app.Err = out, errOut
	root := newRootCmd(app, "test", "none", "none")

	require.NoError(t, app.runPluginList(root, false))

	assert.Contains(t, out.String(), "binpass good")
	assert.Contains(t, out.String(), "binpass broken")
	assert.Contains(t, out.String(), "not executable")
	assert.Contains(t, errOut.String(), "will not run")
}
