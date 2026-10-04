package cli

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRunType covers `binpass type`: the entry's field is sent as
// keystrokes, with the secret arriving over stdin rather than argv.
func TestRunType(t *testing.T) {
	app := newTestApp(t)
	app.set(t, "site/login", "hunter2\nusername: jane\n")

	dir := t.TempDir()
	typingToolStub(t, dir)
	t.Setenv("PATH", dir)

	require.NoError(t, app.runType(context.Background(), "site/login", "password", 0, ""))
	assert.Equal(t, "hunter2", typedText(t))

	require.NoError(t, app.runType(context.Background(), "site/login", "username", 0, ""))
	assert.Equal(t, "jane", typedText(t))
}

// TestRunType_ToolOverride covers --tool: the named backend is used even
// when session autodetection would find nothing to run.
func TestRunType_ToolOverride(t *testing.T) {
	app := newTestApp(t)
	app.set(t, "site/login", "hunter2\n")

	dir := t.TempDir()
	typingToolsStub(t, dir, "xdotool")
	t.Setenv("PATH", dir)
	t.Setenv("WAYLAND_DISPLAY", "")
	t.Setenv("DISPLAY", "")

	require.NoError(t, app.runType(context.Background(), "site/login", "password", 0, "xdotool"))

	assert.Equal(t, "hunter2", typedText(t))
	assert.Equal(t, "xdotool", typedTool(t))
}

// TestRunType_InvalidToolFailsAfterDecrypt covers the backstop: a bogus
// name that reaches the typer errors instead of silently typing through
// autodetection.
func TestRunType_InvalidToolFailsAfterDecrypt(t *testing.T) {
	app := newTestApp(t)
	app.set(t, "site/login", "hunter2\n")

	dir := t.TempDir()
	typingToolsStub(t, dir, "wtype")
	t.Setenv("PATH", dir)
	t.Setenv("WAYLAND_DISPLAY", "wayland-0")

	err := app.runType(context.Background(), "site/login", "password", 0, "wtypo")

	require.Error(t, err)
	assert.ErrorContains(t, err, "wtype", "the error lists the valid names")
	assert.ErrorContains(t, err, "ydotool")
}

// TestTypeCommand_ToolFlag wires the flag through: `binpass type
// --tool=...` reaches the named backend.
func TestTypeCommand_ToolFlag(t *testing.T) {
	app := newTestApp(t)
	app.set(t, "site/login", "hunter2\n")

	dir := t.TempDir()
	typingToolsStub(t, dir, "xdotool")
	t.Setenv("PATH", dir)
	t.Setenv("WAYLAND_DISPLAY", "")
	t.Setenv("DISPLAY", "")

	cmd := newTypeCmd(app.App)
	cmd.SetArgs([]string{"--tool=xdotool", "site/login"})
	require.NoError(t, cmd.Execute())

	assert.Equal(t, "xdotool", typedTool(t))
	assert.Equal(t, "hunter2", typedText(t))
}

// TestTypeCommand_InvalidToolFailsFast covers the validation point: an
// unknown --tool is rejected before the store is touched.
func TestTypeCommand_InvalidToolFailsFast(t *testing.T) {
	app := newTestApp(t)
	app.set(t, "site/login", "hunter2\n")

	// No tool on PATH at all: if the command got as far as typing, it
	// would fail differently — or worse, succeed through a stub.
	t.Setenv("PATH", t.TempDir())

	cmd := newTypeCmd(app.App)
	cmd.SetArgs([]string{"--tool=wtypo", "site/login"})
	err := cmd.Execute()

	require.Error(t, err)
	assert.ErrorContains(t, err, "unknown tool")
}

// TestResolveTyperTool covers the precedence chain: an explicit --tool
// beats the typer.tool setting (which BINPASS_TYPER_TOOL feeds), and an
// explicit --tool=auto cancels it.
func TestResolveTyperTool(t *testing.T) {
	app := newTestApp(t)

	// No setting, no flag: autodetection.
	tool, err := app.resolveTyperTool(false, "auto")
	require.NoError(t, err)
	assert.Equal(t, "auto", tool)

	// The setting is used when the flag is left at its default.
	app.Cfg.TyperTool = "wtype"
	tool, err = app.resolveTyperTool(false, "auto")
	require.NoError(t, err)
	assert.Equal(t, "wtype", tool)

	// An explicit flag wins, even when it is auto cancelling the setting.
	tool, err = app.resolveTyperTool(true, "auto")
	require.NoError(t, err)
	assert.Equal(t, "auto", tool)

	tool, err = app.resolveTyperTool(true, "ydotool")
	require.NoError(t, err)
	assert.Equal(t, "ydotool", tool)

	// A typo in the flag is rejected with the valid names.
	_, err = app.resolveTyperTool(true, "wtypo")
	require.Error(t, err)
	for _, name := range []string{"wtype", "xdotool", "ydotool"} {
		assert.ErrorContains(t, err, name)
	}

	// A typo in the setting must not silently become autodetection.
	app.Cfg.TyperTool = "wtypo"
	_, err = app.resolveTyperTool(false, "auto")
	assert.Error(t, err)
}
