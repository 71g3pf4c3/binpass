package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubPicker puts an executable of the given name on PATH, so that detection
// can be exercised without installing rofi or fzf.
func stubPicker(t *testing.T, names ...string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("executable bit")
	}
	dir := t.TempDir()
	for _, name := range names {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\n"), 0o700)) //nolint:gosec // a test stub.
	}
	t.Setenv("PATH", dir)
}

func TestDetectPickerByName(t *testing.T) {
	stubPicker(t, "rofi", "fzf")

	p, err := detectPicker("rofi")
	require.NoError(t, err)
	assert.Equal(t, "rofi", p.name)

	p, err = detectPicker("fzf")
	require.NoError(t, err)
	assert.Equal(t, "fzf", p.name)
	assert.True(t, p.needsTTY, "fzf draws on the terminal")
}

func TestDetectPickerRejectsUnknownAndMissing(t *testing.T) {
	stubPicker(t, "rofi")

	_, err := detectPicker("nonsense")
	assert.ErrorContains(t, err, "unknown launcher")

	_, err = detectPicker("wofi")
	assert.ErrorContains(t, err, "not installed")
}

func TestDetectPickerPrefersGraphicalInAGraphicalSession(t *testing.T) {
	stubPicker(t, "rofi", "fzf")
	t.Setenv("WAYLAND_DISPLAY", "wayland-0")

	p, err := detectPicker("auto")
	require.NoError(t, err)
	assert.Equal(t, "rofi", p.name, "a keybinding cannot use a terminal picker")
}

func TestDetectPickerPrefersTerminalWithoutADisplay(t *testing.T) {
	stubPicker(t, "rofi", "fzf")
	t.Setenv("WAYLAND_DISPLAY", "")
	t.Setenv("DISPLAY", "")

	p, err := detectPicker("auto")
	require.NoError(t, err)
	assert.Equal(t, "fzf", p.name)
}

func TestDetectPickerFallsBackToWhateverExists(t *testing.T) {
	// Only a graphical picker is installed, but there is no display: it is
	// still better than refusing to run.
	stubPicker(t, "dmenu")
	t.Setenv("WAYLAND_DISPLAY", "")
	t.Setenv("DISPLAY", "")

	p, err := detectPicker("auto")
	require.NoError(t, err)
	assert.Equal(t, "dmenu", p.name)
}

func TestDetectPickerReportsWhenNothingIsInstalled(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	_, err := detectPicker("auto")
	assert.ErrorContains(t, err, "no picker found")
}

func TestPickerArgumentsCarryThePrompt(t *testing.T) {
	for _, p := range pickers() {
		args := p.args("pass")
		joined := ""
		for _, a := range args {
			joined += a + " "
		}
		assert.Contains(t, joined, "pass", "%s must show the prompt", p.name)
	}
}
