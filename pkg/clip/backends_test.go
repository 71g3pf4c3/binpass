package clip

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPasteNeverInvokesAWriter guards the bug where the Wayland backend was
// registered with an empty pasteArgs and wl-copy as its only binary: reading
// the clipboard then ran `wl-copy` with no input, wiping the user's clipboard
// instead of returning its contents.
func TestPasteNeverInvokesAWriter(t *testing.T) {
	writers := map[string]bool{"wl-copy": true, "pbcopy": true}

	for _, b := range backends("clipboard") {
		tl, ok := b.(*tool)
		if !ok {
			continue
		}
		require.NotEmpty(t, tl.bin, "%s: the paste binary must be set", tl.name)
		require.NotEmpty(t, tl.copyBin, "%s: the copy binary must be set", tl.name)
		assert.False(t, writers[tl.bin],
			"%s reads the clipboard with %q, which writes it", tl.name, tl.bin)
	}
}

func TestWaylandIsPreferredOverX11(t *testing.T) {
	// A Wayland session commonly exports DISPLAY too, via Xwayland. Choosing
	// xclip there would write to the compatibility layer, and the secret
	// would never reach the real clipboard.
	all := backends("clipboard")
	require.NotEmpty(t, all)
	assert.Equal(t, "wl-clipboard", all[0].Name())
}

// pbcopyStubs installs recording stubs for pbcopy and pbpaste that share one
// state file, mimicking the single macOS clipboard: pbcopy stores what it read
// on stdin, pbpaste prints it back.
//
// Shell builtins only: the stubs run with a PATH that contains nothing but
// themselves, and /bin/cat does not exist on NixOS either. Only single-line
// secrets round-trip exactly, which is all the copy path needs — the first
// line of an entry is the password.
func pbcopyStubs(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	copyBody := "#!/bin/sh\nIFS= read -r x\nprintf '%s' \"$x\" > \"$CLIP_STATE\"\nprintf '%s\\n' \"$@\" > \"$CLIP_ARGV\"\n"
	pasteBody := "#!/bin/sh\nif [ -f \"$CLIP_STATE\" ]; then\nIFS= read -r x < \"$CLIP_STATE\"\nprintf '%s' \"$x\"\nfi\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pbcopy"), []byte(copyBody), 0o700))   //nolint:gosec // a test stub.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pbpaste"), []byte(pasteBody), 0o700)) //nolint:gosec // a test stub.
	t.Setenv("PATH", dir)
	t.Setenv("CLIP_STATE", filepath.Join(dir, "state.txt"))
	t.Setenv("CLIP_ARGV", filepath.Join(dir, "argv.txt"))
	// No session envs and an empty PATH otherwise: the X11 and Wayland
	// backends must have nothing to attach to, so the pbcopy backend is the
	// only one Detect can reach — as on a bare macOS host.
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")
}

// clipState returns the shared clipboard state file of the pbcopy stubs.
func clipState(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(os.Getenv("CLIP_STATE"))
	require.NoError(t, err)
	return string(data)
}

// TestPbcopyFeedsStdinNotArgv proves the secret travels over the pipe to
// pbcopy, so ps(1) on a macOS host never shows it to other users.
func TestPbcopyFeedsStdinNotArgv(t *testing.T) {
	pbcopyStubs(t)

	b, err := Detect("clipboard")
	require.NoError(t, err)
	require.Equal(t, "pbcopy", b.Name())

	require.NoError(t, b.Copy(t.Context(), "hunter2"))

	assert.Equal(t, "hunter2", clipState(t))
	argv, err := os.ReadFile(os.Getenv("CLIP_ARGV"))
	require.NoError(t, err)
	assert.Empty(t, strings.TrimSpace(string(argv)), "pbcopy must receive the secret on stdin, not in argv")
}

// TestPbcopyPasteReadsBack covers the read half of the backend: pbpaste is
// the paste binary, invoked with no arguments.
func TestPbcopyPasteReadsBack(t *testing.T) {
	pbcopyStubs(t)

	require.NoError(t, os.WriteFile(os.Getenv("CLIP_STATE"), []byte("earlier work"), 0o600))

	b, err := Detect("clipboard")
	require.NoError(t, err)

	got, err := b.Paste(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "earlier work", got)
}

// TestPbcopyAvailableRequiresBothHalves guards the registry wiring: a host
// with only pbcopy installed must not be detected as usable, because reading
// the old contents for the restore would then run a missing binary.
func TestPbcopyAvailableRequiresBothHalves(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pbcopy"), []byte("#!/bin/sh\n"), 0o700)) //nolint:gosec // a test stub.
	t.Setenv("PATH", dir)
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")

	_, err := Detect("clipboard")
	assert.ErrorIs(t, err, ErrNoBackend)
}

// TestCopyWithTimeoutRestoresThroughPbcopy runs the full restore cycle
// through the exec backend rather than the in-memory fake, proving the
// paste/copy plumbing preserves the semantics on the darwin path too.
func TestCopyWithTimeoutRestoresThroughPbcopy(t *testing.T) {
	pbcopyStubs(t)
	require.NoError(t, os.WriteFile(os.Getenv("CLIP_STATE"), []byte("earlier work"), 0o600))

	b, err := Detect("clipboard")
	require.NoError(t, err)

	require.NoError(t, CopyWithTimeout(t.Context(), b, "hunter2", 10*time.Millisecond))

	assert.Equal(t, "earlier work", clipState(t), "the clipboard is handed back as it was found")
}

func TestSelectionReachesEveryBackend(t *testing.T) {
	for _, b := range backends("primary") {
		switch v := b.(type) {
		case *tool:
			joined := ""
			for _, a := range append(v.copyArgs, v.pasteArgs...) {
				joined += a + " "
			}
			if v.name != "pbcopy" {
				assert.Contains(t, joined, "primary", "%s ignores the selection", v.name)
			}
		case *wlClipboard:
			assert.Equal(t, []string{"--primary"}, wlCopyArgs(v.selection))
		}
	}
}

// TestReportsExplainsEveryBackend covers the doctor surface: each
// backend's availability, the reasons for the ones Detect cannot reach,
// and the first available report being the backend Detect returns.
func TestReportsExplainsEveryBackend(t *testing.T) {
	pbcopyStubs(t)

	reports := Reports("clipboard")
	require.NotEmpty(t, reports)

	byName := make(map[string]BackendReport)
	for _, r := range reports {
		byName[r.Name] = r
	}
	assert.True(t, byName["pbcopy"].Available)
	assert.Empty(t, byName["pbcopy"].Missing)
	assert.False(t, byName["xclip"].Available)
	assert.Contains(t, byName["xclip"].Missing, "DISPLAY not set")
	assert.Contains(t, byName["xclip"].Missing, "xclip not on PATH")
	assert.False(t, byName["wl-clipboard"].Available)
	assert.Contains(t, byName["wl-clipboard"].Missing, "WAYLAND_DISPLAY not set")
	assert.Contains(t, byName["wl-clipboard"].Missing, "wl-copy not on PATH")
	assert.Contains(t, byName["wl-clipboard"].Missing, "wl-paste not on PATH")

	// The winner of Reports and the winner of Detect are the same
	// backend, or doctor would explain a choice Detect never makes.
	b, err := Detect("clipboard")
	require.NoError(t, err)
	first := ""
	for _, r := range reports {
		if r.Available {
			first = r.Name
			break
		}
	}
	assert.Equal(t, b.Name(), first)
}

// TestReportsNamesBothHalvesMissing covers pbcopy's split binaries: a host
// with only the writer installed reports the missing reader, which is
// what keeps the restore path from running a missing binary.
func TestReportsNamesBothHalvesMissing(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pbcopy"), []byte("#!/bin/sh\n"), 0o700)) //nolint:gosec // a test stub.
	t.Setenv("PATH", dir)
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")

	for _, r := range Reports("clipboard") {
		if r.Name != "pbcopy" {
			continue
		}
		assert.False(t, r.Available)
		assert.Equal(t, []string{"pbpaste not on PATH"}, r.Missing)
	}
}

// TestReportsWaylandBackendWhenSessionIsRight covers the positive
// wl-clipboard line: with both binaries present and a Wayland session, the
// backend reports available with nothing missing.
func TestReportsWaylandBackendWhenSessionIsRight(t *testing.T) {
	dir := t.TempDir()
	for _, bin := range []string{"wl-copy", "wl-paste"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, bin), []byte("#!/bin/sh\n"), 0o700)) //nolint:gosec // a test stub.
	}
	t.Setenv("PATH", dir)
	t.Setenv("WAYLAND_DISPLAY", "wayland-0")
	t.Setenv("DISPLAY", "")

	reports := Reports("clipboard")

	require.NotEmpty(t, reports)
	assert.Equal(t, "wl-clipboard", reports[0].Name)
	assert.True(t, reports[0].Available)
	assert.Empty(t, reports[0].Missing)
}
