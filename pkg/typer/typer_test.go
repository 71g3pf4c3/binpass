package typer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// typingStub installs a fake wtype that records its arguments and its
// standard input, so a test can prove where the secret actually went.
//
// Shell builtins only: the stub runs with a PATH that contains nothing but
// itself, and /bin/cat does not exist on NixOS either.
func typingStub(t *testing.T, bin string) {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, bin)
	body := "#!/bin/sh\nIFS= read -r x\nprintf '%s' \"$x\" > \"$TYPED_STDIN\"\nprintf '%s\\n' \"$@\" > \"$TYPED_ARGV\"\n"
	require.NoError(t, os.WriteFile(script, []byte(body), 0o700)) //nolint:gosec // a test stub.
	t.Setenv("PATH", dir)
	t.Setenv("TYPED_STDIN", filepath.Join(dir, "stdin.txt"))
	t.Setenv("TYPED_ARGV", filepath.Join(dir, "argv.txt"))
}

// typedStdin returns what the stub was fed on standard input.
func typedStdin(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(os.Getenv("TYPED_STDIN"))
	require.NoError(t, err)
	return string(data)
}

// typedArgv returns the stub's command line as one string.
func typedArgv(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(os.Getenv("TYPED_ARGV"))
	require.NoError(t, err)
	return string(data)
}

// TestType_FeedsStdinNotArgv is the security property of this package: the
// secret travels over the pipe, so ps(1) never shows it to other users.
func TestType_FeedsStdinNotArgv(t *testing.T) {
	typingStub(t, "wtype")
	t.Setenv("WAYLAND_DISPLAY", "wayland-0")

	require.NoError(t, Type(context.Background(), "s3cret pa$$word"))

	assert.Equal(t, "s3cret pa$$word", typedStdin(t))
	assert.NotContains(t, typedArgv(t), "s3cret", "the secret must not appear in argv")
	assert.Equal(t, "-", strings.TrimSpace(typedArgv(t)), "wtype receives only the stdin marker")
}

// TestType_SkipsWaylandToolWithoutWayland covers session gating: wtype is
// skipped when there is no Wayland session, and the X11 tool takes over.
func TestType_SkipsWaylandToolWithoutWayland(t *testing.T) {
	dir := t.TempDir()
	for _, bin := range []string{"wtype", "xdotool"} {
		script := filepath.Join(dir, bin)
		require.NoError(t, os.WriteFile(script, []byte("#!/bin/sh\nIFS= read -r x\nprintf '%s' \"$x\" > \"$TYPED_STDIN\"\nprintf '%s\\n' \"$0\" \"$@\" > \"$TYPED_ARGV\"\n"), 0o700)) //nolint:gosec // a test stub.
	}
	t.Setenv("PATH", dir)
	t.Setenv("TYPED_STDIN", filepath.Join(dir, "stdin.txt"))
	t.Setenv("TYPED_ARGV", filepath.Join(dir, "argv.txt"))
	t.Setenv("DISPLAY", ":0")
	t.Setenv("WAYLAND_DISPLAY", "")

	require.NoError(t, Type(context.Background(), "hunter2"))

	assert.Equal(t, "hunter2", typedStdin(t))
	assert.Contains(t, typedArgv(t), "xdotool")
}

// TestType_NoToolAvailable covers the empty-session error.
func TestType_NoToolAvailable(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	err := Type(context.Background(), "x")

	assert.ErrorIs(t, err, ErrNoTool)
}

// toolStubs installs the named tools as stubs recording which of them ran
// and what it was fed, so a test can prove which backend an override
// selected. Shell builtins only, like typingStub above.
func toolStubs(t *testing.T, bins ...string) {
	t.Helper()
	dir := t.TempDir()
	for _, bin := range bins {
		script := filepath.Join(dir, bin)
		body := "#!/bin/sh\nIFS= read -r x\nprintf '%s' \"$x\" > \"$TYPED_STDIN\"\nprintf '%s\\n' \"${0##*/}\" > \"$TYPED_TOOL\"\n"
		require.NoError(t, os.WriteFile(script, []byte(body), 0o700)) //nolint:gosec // a test stub.
	}
	t.Setenv("PATH", dir)
	t.Setenv("TYPED_STDIN", filepath.Join(dir, "stdin.txt"))
	t.Setenv("TYPED_TOOL", filepath.Join(dir, "tool.txt"))
}

// typedTool returns which tool stub ran last.
func typedTool(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(os.Getenv("TYPED_TOOL"))
	require.NoError(t, err)
	return strings.TrimSpace(string(data))
}

// TestTypeWithTool_ForcesTheNamedTool covers the override: with every
// backend installed and a session that would autodetect wtype, the named
// tool runs instead — and the secret still travels over stdin.
func TestTypeWithTool_ForcesTheNamedTool(t *testing.T) {
	toolStubs(t, "wtype", "xdotool", "ydotool")
	t.Setenv("WAYLAND_DISPLAY", "wayland-0")

	require.NoError(t, TypeWithTool(context.Background(), "xdotool", "s3cret pa$$word"))

	assert.Equal(t, "s3cret pa$$word", typedStdin(t))
	assert.Equal(t, "xdotool", typedTool(t), "the named tool runs, not the detected one")
}

// TestTypeWithTool_IgnoresSessionGates covers why the override exists: a
// forced tool runs even when the session variables autodetection relies
// on are absent, because they lie about the session as often as they
// describe it.
func TestTypeWithTool_IgnoresSessionGates(t *testing.T) {
	toolStubs(t, "wtype")
	t.Setenv("WAYLAND_DISPLAY", "")
	t.Setenv("DISPLAY", "")

	// Autodetection finds nothing here; the override still works.
	assert.ErrorIs(t, Type(context.Background(), "x"), ErrNoTool)
	require.NoError(t, TypeWithTool(context.Background(), "wtype", "hunter2"))
	assert.Equal(t, "hunter2", typedStdin(t))
}

// TestTypeWithTool_UnknownName covers the error contract: an invalid name
// fails with the list of valid ones rather than falling back to
// autodetection.
func TestTypeWithTool_UnknownName(t *testing.T) {
	err := TypeWithTool(context.Background(), "wtypo", "x")
	require.Error(t, err)
	for _, name := range []string{"wtype", "xdotool", "ydotool"} {
		assert.ErrorContains(t, err, name)
	}
}

// TestTypeWithTool_NotInstalled covers the missing-binary error: a forced
// tool must fail loudly, never cascade to another candidate.
func TestTypeWithTool_NotInstalled(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	err := TypeWithTool(context.Background(), "wtype", "x")

	assert.ErrorContains(t, err, "wtype is not installed")
}

// TestParseTool covers the validation the commands run before touching
// the store: every accepted name round-trips, anything else is rejected
// with the valid ones.
func TestParseTool(t *testing.T) {
	for _, name := range append(ToolNames(), "") {
		got, err := ParseTool(name)
		require.NoError(t, err, name)
		assert.Equal(t, name, got)
	}

	for _, name := range []string{"WType", "pass", "auto "} {
		_, err := ParseTool(name)
		assert.Error(t, err, name)
	}
}

// TestReportMirrorsWhatTypeWouldRun is the contract doctor relies on: the
// backend Report names as picked is the one Type actually runs in the
// same session.
func TestReportMirrorsWhatTypeWouldRun(t *testing.T) {
	toolStubs(t, "wtype", "xdotool", "ydotool")
	t.Setenv("WAYLAND_DISPLAY", "wayland-0")

	reports, picked := Report()
	assert.Equal(t, "wtype", picked)
	require.Len(t, reports, 3)

	require.NoError(t, Type(context.Background(), "x"))
	assert.Equal(t, "wtype", typedTool(t))
}

// TestReportNamesWhyEachToolIsUnavailable covers the diagnostic surface:
// the session gate and PATH presence of every backend, and an empty pick
// when nothing clears both.
func TestReportNamesWhyEachToolIsUnavailable(t *testing.T) {
	toolStubs(t, "xdotool")
	t.Setenv("WAYLAND_DISPLAY", "")
	t.Setenv("DISPLAY", "")

	reports, picked := Report()
	assert.Empty(t, picked, "xdotool is installed but DISPLAY gates it off")

	byName := make(map[string]ToolReport)
	for _, r := range reports {
		byName[r.Name] = r
	}
	assert.False(t, byName["wtype"].EnvSet, "no WAYLAND_DISPLAY in the session")
	assert.False(t, byName["wtype"].Installed)
	assert.True(t, byName["xdotool"].Installed)
	assert.Equal(t, "WAYLAND_DISPLAY", byName["wtype"].RequiresEnv)
	assert.Empty(t, byName["ydotool"].RequiresEnv, "ydotool has no session gate")
}

// TestReportPicksTheX11ToolOnAnXSession covers the fallback order: without
// a Wayland session the X11 tool takes over.
func TestReportPicksTheX11ToolOnAnXSession(t *testing.T) {
	toolStubs(t, "xdotool")
	t.Setenv("WAYLAND_DISPLAY", "")
	t.Setenv("DISPLAY", ":0")

	_, picked := Report()

	assert.Equal(t, "xdotool", picked)
}
