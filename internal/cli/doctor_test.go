package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/71g3pf4c3/binpass/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// doctorPath installs empty stubs for the named binaries on an otherwise
// empty PATH and clears the session variables, so a doctor run observes
// exactly what the test placed. Doctor only looks the tools up, it never
// runs them, so the stub bodies can be empty — which also keeps the test
// honest on a machine without /bin/sh tools beyond the builtins.
func doctorPath(t *testing.T, bins ...string) {
	t.Helper()
	dir := t.TempDir()
	for _, bin := range bins {
		require.NoError(t, os.WriteFile(filepath.Join(dir, bin), []byte("#!/bin/sh\n"), 0o700)) //nolint:gosec // a test stub.
	}
	t.Setenv("PATH", dir)
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")
}

// TestDoctorTypingReportsTheSessionPick covers the wtype path: every tool
// installed, a Wayland session, and the reasons for the losers.
func TestDoctorTypingReportsTheSessionPick(t *testing.T) {
	app := newTestApp(t)
	doctorPath(t, "wtype", "xdotool", "ydotool")
	t.Setenv("WAYLAND_DISPLAY", "wayland-0")

	require.NoError(t, app.runDoctor())

	out := app.out.String()
	assert.Contains(t, out, "[typing] OK: wtype\n")
	assert.Contains(t, out, "wtype: selected (WAYLAND_DISPLAY set, on PATH)")
	assert.Contains(t, out, "xdotool: DISPLAY not set")
	assert.Contains(t, out, "ydotool: available")
	assert.Contains(t, out, "tool override: none")
	assert.Contains(t, out, "[tomb]")
}

// TestDoctorTypingFailsWithNoToolInTheSession covers the empty desktop: no
// tool runs, and every backend line says which of its two preconditions is
// missing.
func TestDoctorTypingFailsWithNoToolInTheSession(t *testing.T) {
	app := newTestApp(t)
	doctorPath(t)

	require.NoError(t, app.runDoctor())

	out := app.out.String()
	assert.Contains(t, out, "[typing] FAIL: no typing tool works in this session")
	assert.Contains(t, out, "wtype: WAYLAND_DISPLAY not set, not on PATH")
	assert.Contains(t, out, "[clipboard] FAIL: no clipboard backend works in this session")
	assert.Contains(t, out, "wl-clipboard: unavailable (WAYLAND_DISPLAY not set, wl-copy not on PATH, wl-paste not on PATH)")
	assert.Contains(t, out, "xclip: unavailable (DISPLAY not set, xclip not on PATH)")
	assert.Contains(t, out, "pbcopy: unavailable (pbpaste not on PATH, pbcopy not on PATH)")
}

// TestDoctorTypingHonorsTheConfiguredOverride covers the typer.tool
// setting: it wins over autodetection and is what the verdict reports.
func TestDoctorTypingHonorsTheConfiguredOverride(t *testing.T) {
	app := newTestApp(t)
	doctorPath(t, "ydotool")
	app.Cfg.TyperTool = "ydotool"

	require.NoError(t, app.runDoctor())

	out := app.out.String()
	assert.Contains(t, out, "[typing] OK: ydotool (tool override)")
	assert.Contains(t, out, "tool override: ydotool")
}

// TestDoctorTypingFailsWhenTheOverrideIsNotInstalled covers a configured
// tool that vanished from PATH: the session tool cannot save it, because
// the override is what `binpass type` would run.
func TestDoctorTypingFailsWhenTheOverrideIsNotInstalled(t *testing.T) {
	app := newTestApp(t)
	doctorPath(t)
	app.Cfg.TyperTool = "wtype"

	require.NoError(t, app.runDoctor())

	assert.Contains(t, app.out.String(), "[typing] FAIL: configured tool wtype is not on PATH")
}

// TestDoctorTypingFailsOnAnUnknownOverride covers the deliberately
// unvalidated BINPASS_TYPER_TOOL value reaching doctor.
func TestDoctorTypingFailsOnAnUnknownOverride(t *testing.T) {
	app := newTestApp(t)
	doctorPath(t)
	app.Cfg.TyperTool = "wtypo"

	require.NoError(t, app.runDoctor())

	assert.Contains(t, app.out.String(), `[typing] FAIL: configured tool "wtypo" is unknown`)
}

// TestDoctorClipboardReportsTheSessionBackend covers the wl-clipboard path
// and the per-backend reasons for the X11 and macOS losers.
func TestDoctorClipboardReportsTheSessionBackend(t *testing.T) {
	app := newTestApp(t)
	doctorPath(t, "wl-copy", "wl-paste")
	t.Setenv("WAYLAND_DISPLAY", "wayland-0")

	require.NoError(t, app.runDoctor())

	out := app.out.String()
	assert.Contains(t, out, "[clipboard] OK: wl-clipboard\n")
	assert.Contains(t, out, "wl-clipboard: detected")
	assert.Contains(t, out, "xclip: unavailable (DISPLAY not set, xclip not on PATH)")
}

// TestDoctorIdentitiesReportsSourcesAndProbeOK covers the healthy age
// path: the explicit source is named with its identity count, and the
// probe proves the key matches the store's recipients.
func TestDoctorIdentitiesReportsSourcesAndProbeOK(t *testing.T) {
	app := newTestApp(t)
	doctorPath(t)

	require.NoError(t, app.runDoctor())

	out := app.out.String()
	assert.Contains(t, out, "[identities] OK: 1 identity from 1 source")
	assert.Contains(t, out, app.Cfg.Identity+": 1 identity (file, explicit)")
	assert.Contains(t, out, "probe: OK (an identity decrypts data encrypted to the store's recipients)")
}

// TestDoctorIdentitiesProbeFailsOnKeyMismatch covers the case the probe
// exists for: identities load, but they belong to a different store than
// .age-recipients lists.
func TestDoctorIdentitiesProbeFailsOnKeyMismatch(t *testing.T) {
	app := newTestApp(t)
	doctorPath(t)
	other, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(app.Cfg.Identity, []byte(other.String()+"\n"), 0o600))

	require.NoError(t, app.runDoctor())

	out := app.out.String()
	assert.Contains(t, out, "[identities] FAIL: the identity probe failed")
	assert.Contains(t, out, "probe: FAIL (none of the 1 probed identities decrypt data")
	assert.Contains(t, out, "the key and the store do not match")
}

// TestDoctorIdentitiesSkipTheProbeForPluginIdentities covers the hardware
// token path: a plugin identity is counted and named, but never unwrapped,
// because that would touch the token.
func TestDoctorIdentitiesSkipTheProbeForPluginIdentities(t *testing.T) {
	app := newTestApp(t)
	doctorPath(t)
	require.NoError(t, os.WriteFile(app.Cfg.Identity, []byte("AGE-PLUGIN-YUBIKEY-1QYPQXPQTZJ3QV\n"), 0o600))

	require.NoError(t, app.runDoctor())

	out := app.out.String()
	assert.Contains(t, out, "[identities] OK: 1 identity from 1 source")
	assert.Contains(t, out, "1 identity (plugin, explicit)")
	assert.Contains(t, out, "probe: skipped (only plugin identities; hardware tokens are not touched)")
}

// TestDoctorIdentitiesFailWithNoneFound covers the empty key ring: the
// failure names every location that was searched, indented under the
// verdict.
func TestDoctorIdentitiesFailWithNoneFound(t *testing.T) {
	app := newTestApp(t)
	doctorPath(t)
	app.Cfg.Identity = ""
	// Point every fallback location at directories the test owns: under
	// env -i the defaults reach into the real home, and a developer with
	// a key there must not change this test's outcome.
	t.Setenv("BINPASS_IDENTITY", "")
	t.Setenv("PASSAGE_IDENTITIES_FILE", "")
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "cfg"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(t.TempDir(), "data"))

	require.NoError(t, app.runDoctor())

	out := app.out.String()
	assert.Contains(t, out, "[identities] FAIL: identity: no identity found")
	assert.Contains(t, out, "searched:")
}

// TestDoctorSkipsTheProbeInAGpgStore covers a store with .gpg-id only:
// there are no age recipients to prove a match against, so the probe is
// skipped rather than failed.
func TestDoctorSkipsTheProbeInAGpgStore(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "store")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".gpg-id"), []byte("alice@example.invalid\n"), 0o600))

	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	keyFile := filepath.Join(tmp, "identity.key")
	require.NoError(t, os.WriteFile(keyFile, []byte(id.String()+"\n"), 0o600))

	cfg := config.Default()
	cfg.Dir = dir
	cfg.Identity = keyFile
	app := &App{Cfg: cfg, Out: &bytes.Buffer{}, Err: &bytes.Buffer{}, In: strings.NewReader("")}
	doctorPath(t)

	require.NoError(t, app.runDoctor())

	out := app.Out.(*bytes.Buffer).String()
	assert.Contains(t, out, "probe: skipped (no .age-recipients in the store)")
	assert.Contains(t, out, "[identities] OK")
	assert.Contains(t, out, "[store] OK: initialised")
	assert.Contains(t, out, ".gpg-id: present")
}

// TestDoctorStoreReportsTheBackendMix covers the entry census: .age and
// .gpg counts, and the recipients file with its line count.
func TestDoctorStoreReportsTheBackendMix(t *testing.T) {
	app := newTestApp(t)
	doctorPath(t)
	app.set(t, "alice", "hunter2\n")
	app.set(t, "web/bob", "hunter3\n")
	require.NoError(t, os.WriteFile(filepath.Join(app.dir, "legacy.gpg"), []byte("not really encrypted"), 0o600))

	require.NoError(t, app.runDoctor())

	out := app.out.String()
	assert.Contains(t, out, "[store] OK: initialised")
	assert.Contains(t, out, "entries: 2 .age entries, 1 .gpg entry")
	assert.Contains(t, out, ".age-recipients: present, 1 recipient")
	assert.Contains(t, out, ".gpg-id: absent")
}

// TestDoctorStoreFailsWhenNotInitialised covers a directory that exists
// but carries no recipients file for any backend.
func TestDoctorStoreFailsWhenNotInitialised(t *testing.T) {
	app := newTestApp(t)
	doctorPath(t)
	empty := filepath.Join(t.TempDir(), "store")
	require.NoError(t, os.MkdirAll(empty, 0o700))
	app.Cfg.Dir = empty

	require.NoError(t, app.runDoctor())

	out := app.out.String()
	assert.Contains(t, out, "[store] FAIL: not initialised")
	assert.Contains(t, out, ".age-recipients: absent")
	assert.Contains(t, out, ".gpg-id: absent")
}

// TestDoctorStoreFailsWhenTheDirectoryIsMissing covers a configured store
// path that does not exist at all.
func TestDoctorStoreFailsWhenTheDirectoryIsMissing(t *testing.T) {
	app := newTestApp(t)
	doctorPath(t)
	app.Cfg.Dir = filepath.Join(t.TempDir(), "does-not-exist")

	require.NoError(t, app.runDoctor())

	assert.Contains(t, app.out.String(), "[store] FAIL: store directory")
}
