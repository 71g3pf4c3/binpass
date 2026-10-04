package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/71g3pf4c3/binpass/pkg/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests exercise the full pass/gopass import path: a real gpg source
// store in an isolated GNUPGHOME, decrypted through the external binary and
// re-encrypted into the destination store. Builtins-only stubs cannot fake
// real crypto, so the gpg binary is required; without it the tests skip, the
// same precedent as the golden suite. The developer's own keyring and store
// are never touched.

// cliGPGUID identifies the throwaway key generated for CLI import tests.
const cliGPGUID = "binpass-cli-import@example.invalid"

// newTestGPGHome generates an unprotected throwaway key in an isolated
// GNUPGHOME and returns its recipient.
func newTestGPGHome(t *testing.T) crypto.Recipient {
	t.Helper()
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not on PATH: cannot exercise pass import decryption")
	}
	// Under /tmp, not t.TempDir(): gpg-agent's socket path is limited to
	// ~108 bytes, and long TMPDIR-derived paths silently break the agent.
	home, err := os.MkdirTemp("", "binpass-cli-gnupg-*")
	require.NoError(t, err)
	require.NoError(t, os.Chmod(home, 0o700))
	t.Setenv("GNUPGHOME", home)
	t.Cleanup(func() {
		_ = exec.Command("gpgconf", "--homedir", home, "--kill", "all").Run() //nolint:gosec // fixed arguments in tests.
		_ = os.RemoveAll(home)
	})

	gen := exec.Command("gpg", "--batch", "--passphrase", "", "--quick-generate-key", cliGPGUID, "default", "default", "never") //nolint:gosec // fixed arguments in tests.
	gen.Env = append(os.Environ(), "GNUPGHOME="+home)
	if out, err := gen.CombinedOutput(); err != nil {
		t.Skipf("cannot generate a test gpg key: %v: %s", err, out)
	}
	return crypto.Recipient(cliGPGUID)
}

// newTestPassStore writes a gpg-encrypted source store and returns its
// directory.
func newTestPassStore(t *testing.T, entries map[string]string) string {
	t.Helper()
	rcp := newTestGPGHome(t)

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".gpg-id"), []byte(rcp.String()+"\n"), 0o600))
	g := crypto.NewGPG(dir, "", nil)
	for name, plain := range entries {
		path := filepath.Join(dir, filepath.FromSlash(name)+".gpg")
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
		f, err := os.Create(path) //nolint:gosec // inside the test's own temp dir.
		require.NoError(t, err)
		require.NoError(t, g.Encrypt(f, []byte(plain), []crypto.Recipient{rcp}))
		require.NoError(t, f.Close())
	}
	return dir
}

func TestRunImport_PassDecryptsAndReencrypts(t *testing.T) {
	// The body mixes structured fields, an OTP URI and free-form lines in a
	// non-canonical order: the transfer must preserve it byte for byte
	// rather than rebuild it from structured Entry fields.
	plaintext := "hunter2\notpauth://totp/x?secret=JBSWY3DP\nusername: alice\na free-form line\n"
	srcDir := newTestPassStore(t, map[string]string{"Social/Twitter": plaintext})

	app := newTestApp(t)
	require.NoError(t, app.runImport(srcDir, "pass", false, false, ""))

	s, err := app.Store()
	require.NoError(t, err)
	names, err := s.List("")
	require.NoError(t, err)
	assert.Equal(t, []string{"Social/Twitter"}, names)

	sec, err := s.Get("Social/Twitter")
	require.NoError(t, err)
	assert.Equal(t, plaintext, string(sec.Bytes()), "source plaintext must survive the transfer verbatim")

	// Re-encrypted for the destination's recipients, not copied: the
	// destination store is age-backed, so the entry lands as .age.
	assert.FileExists(t, filepath.Join(app.dir, "Social", "Twitter.age"))
	_, err = os.Stat(filepath.Join(app.dir, "Social", "Twitter.gpg"))
	assert.ErrorIs(t, err, os.ErrNotExist, "the source .gpg file must not be copied verbatim")

	assert.NotContains(t, app.errOut.String(), "could not be decrypted")
}

func TestRunImport_GopassFormat(t *testing.T) {
	srcDir := newTestPassStore(t, map[string]string{"Servers/Edge": "root-password\n"})

	app := newTestApp(t)
	require.NoError(t, app.runImport(srcDir, "gopass", false, false, ""))

	s, err := app.Store()
	require.NoError(t, err)
	sec, err := s.Get("Servers/Edge")
	require.NoError(t, err)
	assert.Equal(t, "root-password", sec.Password())
}

func TestRunImport_PassUndecryptableFallsBack(t *testing.T) {
	srcDir := newTestPassStore(t, nil)
	// Valid file, invalid OpenPGP: the gpg backend fails to decrypt it.
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "Broken.gpg"), []byte("not openpgp data"), 0o600))

	app := newTestApp(t)
	require.NoError(t, app.runImport(srcDir, "pass", false, false, ""),
		"one undecryptable entry must not fail the whole import")

	// The entry arrives with its ciphertext as an attachment, recoverable by
	// manual decryption, and the operator is told.
	s, err := app.Store()
	require.NoError(t, err)
	sec, err := s.Get("Broken")
	require.NoError(t, err)
	assert.Empty(t, sec.Password(), "nothing was decrypted, so there is no password line beyond the metadata")
	att, err := s.Get("Broken/_ciphertext.gpg.b64")
	require.NoError(t, err)
	assert.NotEmpty(t, att.Password())
	assert.Contains(t, app.errOut.String(), "could not be decrypted")
}

func TestRunImport_PassDryRunWritesNothing(t *testing.T) {
	srcDir := newTestPassStore(t, map[string]string{"Social/Twitter": "hunter2\n"})

	app := newTestApp(t)
	require.NoError(t, app.runImport(srcDir, "pass", true, false, ""))

	s, err := app.Store()
	require.NoError(t, err)
	names, err := s.List("")
	require.NoError(t, err)
	assert.Empty(t, names, "dry-run must not write")
	assert.Contains(t, app.out.String(), "Social/Twitter")
}
