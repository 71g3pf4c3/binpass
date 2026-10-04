package cli

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/71g3pf4c3/binpass/pkg/otp"
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

// pickingPicker stubs a picker that records what it was fed and answers with
// a fixed choice, the way rofi answers the entry the user selected.
func pickingPicker(t *testing.T, choice string) {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "rofi")
	// Shell builtins only: the stub runs with a PATH that contains nothing
	// but itself, and /bin/cat does not exist on NixOS either.
	body := "#!/bin/sh\nwhile IFS= read -r line; do printf '%s\\n' \"$line\" >> \"$MENU_STDIN\"; done\necho \"" + choice + "\"\n"
	require.NoError(t, os.WriteFile(script, []byte(body), 0o700)) //nolint:gosec // a test stub.
	t.Setenv("PATH", dir)
	t.Setenv("MENU_STDIN", filepath.Join(dir, "stdin.txt"))
}

// menuStdin returns what the picker was fed last.
func menuStdin(t *testing.T) []string {
	t.Helper()
	v := os.Getenv("MENU_STDIN")
	require.NotEmpty(t, v, "pickingPicker must run first")
	data, err := os.ReadFile(v)
	require.NoError(t, err)
	var names []string
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if line != "" {
			names = append(names, line)
		}
	}
	return names
}

func TestSortEntries(t *testing.T) {
	names := []string{"b/entry", "a/entry", "c/entry"}
	newer := time.Now()
	older := newer.Add(-time.Hour)
	usage := menuUsage{
		"a/entry": {Count: 1, Last: older},
		"c/entry": {Count: 5, Last: newer},
	}

	assert.Equal(t, []string{"a/entry", "b/entry", "c/entry"}, sortEntries(names, "name", false, nil))
	assert.Equal(t, []string{"c/entry", "a/entry", "b/entry"}, sortEntries(names, "frequent", false, usage),
		"most chosen first, ties by name")
	assert.Equal(t, []string{"c/entry", "a/entry", "b/entry"}, sortEntries(names, "recent", false, usage),
		"most recent first")
	assert.Equal(t, []string{"c/entry", "a/entry", "b/entry"}, sortEntries(names, "recent", false, usage))
	assert.Equal(t, []string{"c/entry", "b/entry", "a/entry"}, sortEntries(names, "name", true, nil),
		"reverse flips the sorted order")
}

func TestMenuUsageRoundTrip(t *testing.T) {
	// The history lives in the state directory; pointing it at a scratch
	// dir keeps the round trip away from the developer's real menu history
	// and makes the test pass in the Nix build sandbox, where the real
	// state directory is not writable.
	t.Setenv("BINPASS_STATE_DIR", t.TempDir())

	usage := menuUsage{}
	usage.mark("a")
	usage.mark("a")
	usage.mark("b")
	saveMenuUsage(usage)

	loaded := loadMenuUsage()
	a, ok := loaded["a"]
	require.True(t, ok, "the saved entry must load back")
	assert.Equal(t, 2, a.Count)
	b, ok := loaded["b"]
	require.True(t, ok, "the saved entry must load back")
	assert.Equal(t, 1, b.Count)
	assert.False(t, a.Last.IsZero())
}

// TestRunMenu_FrequentSortOrdersThePickerList covers the whole loop: a
// choice is recorded, and the next menu feeds the picker its entries with
// the chosen one floated to the top.
func TestRunMenu_FrequentSortOrdersThePickerList(t *testing.T) {
	app := newTestApp(t)
	app.set(t, "zeta", "one\n")
	app.set(t, "alpha", "two\n")

	// First run: alphabetical, and the user picks zeta.
	pickingPicker(t, "zeta")
	require.NoError(t, app.runMenu(context.Background(), menuOpts{launcher: "rofi", field: "password", print: true, sort: "frequent"}))
	assert.Equal(t, []string{"alpha", "zeta"}, menuStdin(t), "no history yet: plain name order")
	assert.Contains(t, app.out.String(), "one", "the picked entry's password is printed")

	// Second run: zeta was used, so it leads.
	pickingPicker(t, "alpha")
	require.NoError(t, app.runMenu(context.Background(), menuOpts{launcher: "rofi", field: "password", print: true, sort: "frequent"}))
	assert.Equal(t, []string{"zeta", "alpha"}, menuStdin(t), "the used entry floats to the top")
}

// TestRunMenu_RecentSortOrdersByLastUse covers --sort=recent: the entry
// chosen later leads even with a smaller count.
func TestRunMenu_RecentSortOrdersByLastUse(t *testing.T) {
	app := newTestApp(t)
	app.set(t, "often", "one\n")
	app.set(t, "lately", "two\n")

	pickingPicker(t, "often")
	require.NoError(t, app.runMenu(context.Background(), menuOpts{launcher: "rofi", field: "password", print: true, sort: "recent"}))
	time.Sleep(10 * time.Millisecond) // a measurable gap between the two uses
	pickingPicker(t, "lately")
	require.NoError(t, app.runMenu(context.Background(), menuOpts{launcher: "rofi", field: "password", print: true, sort: "recent"}))

	// The list the picker is fed is ordered before the current choice is
	// recorded, so the ranking shows up on the next run.
	pickingPicker(t, "often")
	require.NoError(t, app.runMenu(context.Background(), menuOpts{launcher: "rofi", field: "password", print: true, sort: "recent"}))
	assert.Equal(t, []string{"lately", "often"}, menuStdin(t), "the most recently used entry leads")
}

// TestRunMenu_OTPField covers --field=otp: the menu emits the current code,
// not the first line — the gap that kept 2FA entries out of the picker flow.
func TestRunMenu_OTPField(t *testing.T) {
	app := newTestApp(t)
	uri := "otpauth://totp/example?secret=JBSWY3DPEHPK3PXP"
	app.set(t, "twofa/github", "hunter2\n"+uri+"\n")

	cfg, err := otp.Parse(uri)
	require.NoError(t, err)
	before, err := cfg.Code(time.Now())
	require.NoError(t, err)

	pickingPicker(t, "twofa/github")
	require.NoError(t, app.runMenu(context.Background(), menuOpts{launcher: "rofi", field: "otp", print: true}))

	got := strings.TrimSpace(app.out.String())
	after, err := cfg.Code(time.Now())
	require.NoError(t, err)
	// A window rollover mid-test changes the code; either side of the
	// boundary is a correct answer.
	if got != before && got != after {
		t.Fatalf("menu printed %q, want the current TOTP code (%q or %q)", got, before, after)
	}
	assert.NotEqual(t, "hunter2", got, "the code, not the password line")
}

// typingToolStub installs a fake wtype alongside whatever stubs already
// live on PATH, recording what it was fed on standard input. It needs a
// Wayland session to be picked, which tests declare explicitly.
func typingToolStub(t *testing.T, dir string) {
	t.Helper()
	script := filepath.Join(dir, "wtype")
	body := "#!/bin/sh\nIFS= read -r x\nprintf '%s' \"$x\" > \"$TYPED_STDIN\"\n"
	require.NoError(t, os.WriteFile(script, []byte(body), 0o700)) //nolint:gosec // a test stub.
	t.Setenv("TYPED_STDIN", filepath.Join(dir, "typed.txt"))
	t.Setenv("WAYLAND_DISPLAY", "wayland-0")
}

// typedText returns what the typing tool last received.
func typedText(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(os.Getenv("TYPED_STDIN"))
	require.NoError(t, err)
	return string(data)
}

// typingToolsStub installs the named typing tools, each recording which of
// them ran and what it was fed, so a test can prove which backend a
// --tool override selected. Unlike typingToolStub it needs no session
// variable: the override, not the detection, is what is under test.
func typingToolsStub(t *testing.T, dir string, names ...string) {
	t.Helper()
	for _, name := range names {
		script := filepath.Join(dir, name)
		// Shell builtins only: the stubs run with a PATH that contains
		// nothing but themselves.
		body := "#!/bin/sh\nIFS= read -r x\nprintf '%s' \"$x\" > \"$TYPED_STDIN\"\nprintf '%s\\n' \"${0##*/}\" > \"$TYPED_TOOL\"\n"
		require.NoError(t, os.WriteFile(script, []byte(body), 0o700)) //nolint:gosec // a test stub.
	}
	t.Setenv("TYPED_STDIN", filepath.Join(dir, "typed.txt"))
	t.Setenv("TYPED_TOOL", filepath.Join(dir, "tool.txt"))
}

// typedTool returns which typing tool ran last.
func typedTool(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(os.Getenv("TYPED_TOOL"))
	require.NoError(t, err)
	return strings.TrimSpace(string(data))
}

// TestRunMenu_Type covers --type: the chosen entry is typed into the
// focused window instead of touching the clipboard.
func TestRunMenu_Type(t *testing.T) {
	app := newTestApp(t)
	app.set(t, "site/login", "s3cret\n")

	// One stub directory serves both the picker and the typing tool: the
	// menu runs both with the PATH it is given.
	dir := t.TempDir()
	choice := filepath.Join(dir, "rofi")
	require.NoError(t, os.WriteFile(choice, []byte("#!/bin/sh\nwhile IFS= read -r line; do :; done\necho site/login\n"), 0o700)) //nolint:gosec // a test stub.
	typingToolStub(t, dir)
	t.Setenv("PATH", dir)

	require.NoError(t, app.runMenu(context.Background(), menuOpts{launcher: "rofi", field: "password", typeIt: true}))

	assert.Equal(t, "s3cret", typedText(t), "the password is typed")
}

// TestRunOTPMenu_TypesCode covers `otp menu`: the picked entry's code is
// computed and typed in one motion.
func TestRunOTPMenu_TypesCode(t *testing.T) {
	app := newTestApp(t)
	app.set(t, "twofa/github", "hunter2\notpauth://totp/example?secret=JBSWY3DPEHPK3PXP\n")

	dir := t.TempDir()
	choice := filepath.Join(dir, "rofi")
	require.NoError(t, os.WriteFile(choice, []byte("#!/bin/sh\nwhile IFS= read -r line; do :; done\necho twofa/github\n"), 0o700)) //nolint:gosec // a test stub.
	typingToolStub(t, dir)
	t.Setenv("PATH", dir)

	require.NoError(t, app.runMenu(context.Background(), menuOpts{launcher: "rofi", field: "otp", typeIt: true}))

	code := typedText(t)
	assert.Regexp(t, `^\d{6}$`, code, "a six-digit TOTP code is typed")
	assert.NotEqual(t, "hunter2", code, "the code, not the password line")
}

func TestOTPKnownRoundTrip(t *testing.T) {
	// The cache lives in the state directory; pointing it at a scratch dir
	// keeps the round trip away from the developer's real menu ranking.
	t.Setenv("BINPASS_STATE_DIR", t.TempDir())

	rememberOTPKnown("a")
	when, ok := loadOTPKnown()["a"]
	require.True(t, ok, "a remembered entry must load back")
	assert.False(t, when.IsZero())

	forgetOTPKnown("a")
	_, ok = loadOTPKnown()["a"]
	assert.False(t, ok, "a forgotten entry must not load back")
}

// TestRunMenu_OTPFieldFloatsKnownEntries covers the otp menu learning loop:
// producing a code once floats the entry above the plain passwords on the
// next run, without the menu ever decrypting the store to find out.
func TestRunMenu_OTPFieldFloatsKnownEntries(t *testing.T) {
	app := newTestApp(t)
	app.set(t, "alpha/plain", "hunter2\n")
	app.set(t, "zeta/twofa", "hunter2\notpauth://totp/example?secret=JBSWY3DPEHPK3PXP\n")

	// First run: nothing is known yet, so plain name order reaches the
	// picker and the pick itself teaches the menu.
	pickingPicker(t, "zeta/twofa")
	require.NoError(t, app.runMenu(context.Background(), menuOpts{launcher: "rofi", field: "otp", print: true}))
	assert.Equal(t, []string{"alpha/plain", "zeta/twofa"}, menuStdin(t), "nothing known yet: name order")
	assert.Regexp(t, `^\d{6}$`, strings.TrimSpace(app.out.String()), "the code, not the password line")

	// Second run: zeta/twofa has produced a code, so it leads.
	pickingPicker(t, "zeta/twofa")
	require.NoError(t, app.runMenu(context.Background(), menuOpts{launcher: "rofi", field: "otp", print: true}))
	assert.Equal(t, []string{"zeta/twofa", "alpha/plain"}, menuStdin(t), "the entry that has produced a code leads")

	// The ranking must survive --reverse: flipping a name sort must not
	// bury the 2FA entries under the plain passwords again.
	pickingPicker(t, "zeta/twofa")
	require.NoError(t, app.runMenu(context.Background(), menuOpts{launcher: "rofi", field: "otp", print: true, reverse: true}))
	assert.Equal(t, []string{"zeta/twofa", "alpha/plain"}, menuStdin(t), "known OTP entries still lead under --reverse")
}

// TestRunMenu_OTPFieldForgetsEntriesWithoutURI covers the self-healing: a
// stale cache entry that can no longer produce a code is dropped on the
// failed pick, so it stops floating on the next run.
func TestRunMenu_OTPFieldForgetsEntriesWithoutURI(t *testing.T) {
	app := newTestApp(t)
	app.set(t, "plain", "hunter2\n")
	rememberOTPKnown("plain") // stale knowledge, e.g. the URI was edited out

	pickingPicker(t, "plain")
	err := app.runMenu(context.Background(), menuOpts{launcher: "rofi", field: "otp", print: true})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "plain has no otpauth:// URI")

	_, ok := loadOTPKnown()["plain"]
	assert.False(t, ok, "the failed pick must self-heal the cache")
}

// TestRunOTP_TeachesTheOtpMenu covers `binpass otp` feeding the same cache:
// any flow that produces a code makes the next `otp menu` run float the
// entry to the top.
func TestRunOTP_TeachesTheOtpMenu(t *testing.T) {
	app := newTestApp(t)
	app.set(t, "site", "hunter2\notpauth://totp/example?secret=JBSWY3DPEHPK3PXP\n")

	require.NoError(t, app.runOTP(context.Background(), "site", false, false, false))
	_, ok := loadOTPKnown()["site"]
	assert.True(t, ok, "a code produced through the otp command must be remembered")
}

// TestRunOTP_WatchTeachesTheOtpMenu covers --watch feeding the cache too:
// watching an entry's codes roll over proves it can produce them.
func TestRunOTP_WatchTeachesTheOtpMenu(t *testing.T) {
	app := newTestApp(t)
	app.set(t, "site", "hunter2\notpauth://totp/example?secret=JBSWY3DPEHPK3PXP\n")

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	require.NoError(t, app.runOTP(ctx, "site", false, true, false))

	_, ok := loadOTPKnown()["site"]
	assert.True(t, ok, "a watched entry must be remembered")
}

// TestMenuCommand_ToolFlag wires the flag through: `binpass menu --type
// --tool=...` reaches the named backend even without a session that
// autodetection would accept.
func TestMenuCommand_ToolFlag(t *testing.T) {
	app := newTestApp(t)
	app.set(t, "site/login", "s3cret\n")

	dir := t.TempDir()
	choice := filepath.Join(dir, "rofi")
	require.NoError(t, os.WriteFile(choice, []byte("#!/bin/sh\nwhile IFS= read -r line; do :; done\necho site/login\n"), 0o700)) //nolint:gosec // a test stub.
	typingToolsStub(t, dir, "xdotool")
	t.Setenv("PATH", dir)
	t.Setenv("WAYLAND_DISPLAY", "")
	t.Setenv("DISPLAY", "")

	cmd := newMenuCmd(app.App)
	cmd.SetArgs([]string{"--type", "--tool=xdotool"})
	require.NoError(t, cmd.Execute())

	assert.Equal(t, "xdotool", typedTool(t))
	assert.Equal(t, "s3cret", typedText(t))
}

// TestMenuCommand_ToolFromConfig covers the setting path: what
// BINPASS_TYPER_TOOL and typer.tool resolve to is used when --tool is
// not passed.
func TestMenuCommand_ToolFromConfig(t *testing.T) {
	app := newTestApp(t)
	app.set(t, "site/login", "s3cret\n")
	app.Cfg.TyperTool = "ydotool"

	dir := t.TempDir()
	choice := filepath.Join(dir, "rofi")
	require.NoError(t, os.WriteFile(choice, []byte("#!/bin/sh\nwhile IFS= read -r line; do :; done\necho site/login\n"), 0o700)) //nolint:gosec // a test stub.
	typingToolsStub(t, dir, "ydotool")
	t.Setenv("PATH", dir)

	cmd := newMenuCmd(app.App)
	cmd.SetArgs([]string{"--type"})
	require.NoError(t, cmd.Execute())

	assert.Equal(t, "ydotool", typedTool(t))
	assert.Equal(t, "s3cret", typedText(t))
}

// TestOTPMenuCommand_ToolFlag covers the inheritance: `binpass otp menu`
// carries the same --tool flag as `binpass menu`.
func TestOTPMenuCommand_ToolFlag(t *testing.T) {
	app := newTestApp(t)
	app.set(t, "twofa/github", "hunter2\notpauth://totp/example?secret=JBSWY3DPEHPK3PXP\n")

	dir := t.TempDir()
	choice := filepath.Join(dir, "rofi")
	require.NoError(t, os.WriteFile(choice, []byte("#!/bin/sh\nwhile IFS= read -r line; do :; done\necho twofa/github\n"), 0o700)) //nolint:gosec // a test stub.
	typingToolsStub(t, dir, "ydotool")
	t.Setenv("PATH", dir)
	t.Setenv("WAYLAND_DISPLAY", "")
	t.Setenv("DISPLAY", "")

	cmd := newOTPCmdMenu(app.App)
	cmd.SetArgs([]string{"--tool=ydotool"})
	require.NoError(t, cmd.Execute())

	assert.Equal(t, "ydotool", typedTool(t))
	assert.Regexp(t, `^\d{6}$`, typedText(t), "a six-digit TOTP code is typed")
}
