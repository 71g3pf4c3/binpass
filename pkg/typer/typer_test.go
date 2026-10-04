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
