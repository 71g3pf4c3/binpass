package crypto_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/71g3pf4c3/binpass/pkg/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// gpgKeyUID identifies the throwaway key generated for the GPG tests.
const gpgKeyUID = "binpass-test@example.invalid"

// newGPGHome creates an isolated GNUPGHOME holding one unprotected test key
// and returns its recipient. The test is skipped when gpg is unavailable.
func newGPGHome(t *testing.T) crypto.Recipient {
	t.Helper()
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not on PATH")
	}
	// GNUPGHOME lives under /tmp: gpg-agent's socket path is limited to ~108
	// bytes and long TMPDIR-derived paths silently break agent startup.
	home, err := os.MkdirTemp("", "binpass-gnupg-*")
	require.NoError(t, err)
	require.NoError(t, os.Chmod(home, 0o700))
	t.Setenv("GNUPGHOME", home)
	t.Cleanup(func() {
		_ = exec.Command("gpgconf", "--homedir", home, "--kill", "all").Run()
		_ = os.RemoveAll(home)
	})

	gen := exec.Command("gpg", "--batch", "--passphrase", "", "--quick-generate-key", gpgKeyUID, "default", "default", "never")
	gen.Env = append(os.Environ(), "GNUPGHOME="+home)
	if out, err := gen.CombinedOutput(); err != nil {
		t.Skipf("cannot generate a test gpg key: %v: %s", err, out)
	}
	return crypto.Recipient(gpgKeyUID)
}

func TestGPGRoundTrip(t *testing.T) {
	rcp := newGPGHome(t)
	g := crypto.NewGPG(t.TempDir(), "", nil)
	require.NoError(t, g.Available())

	plaintext := []byte("hunter2\nusername: alice\n")
	var buf bytes.Buffer
	require.NoError(t, g.Encrypt(&buf, plaintext, []crypto.Recipient{rcp}))
	assert.NotContains(t, buf.String(), "hunter2")

	got, err := g.Decrypt(&buf)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)
}

func TestGPGCiphertextIsReadableByPass(t *testing.T) {
	rcp := newGPGHome(t)
	if _, err := exec.LookPath("pass"); err != nil {
		t.Skip("pass not on PATH")
	}
	store := t.TempDir()
	t.Setenv("PASSWORD_STORE_DIR", store)
	require.NoError(t, os.WriteFile(filepath.Join(store, ".gpg-id"), []byte(rcp.String()+"\n"), 0o600))

	g := crypto.NewGPG(store, "", nil)
	f, err := os.Create(filepath.Join(store, "example.gpg"))
	require.NoError(t, err)
	require.NoError(t, g.Encrypt(f, []byte("hunter2\n"), []crypto.Recipient{rcp}))
	require.NoError(t, f.Close())

	out, err := exec.Command("pass", "show", "example").CombinedOutput()
	require.NoError(t, err, "pass must read what binpass wrote: %s", out)
	assert.Equal(t, "hunter2", strings.TrimSpace(string(out)))
}

func TestGPGReadsWhatPassWrote(t *testing.T) {
	rcp := newGPGHome(t)
	if _, err := exec.LookPath("pass"); err != nil {
		t.Skip("pass not on PATH")
	}
	store := t.TempDir()
	t.Setenv("PASSWORD_STORE_DIR", store)
	require.NoError(t, os.WriteFile(filepath.Join(store, ".gpg-id"), []byte(rcp.String()+"\n"), 0o600))

	insert := exec.Command("pass", "insert", "--multiline", "example")
	insert.Stdin = strings.NewReader("hunter2\nurl: x\n")
	out, err := insert.CombinedOutput()
	require.NoError(t, err, "%s", out)

	f, err := os.Open(filepath.Join(store, "example.gpg"))
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	got, err := crypto.NewGPG(store, "", nil).Decrypt(f)
	require.NoError(t, err)
	assert.Equal(t, "hunter2\nurl: x\n", string(got))
}

func TestGPGEncryptWithoutRecipients(t *testing.T) {
	g := crypto.NewGPG(t.TempDir(), "", nil)
	assert.ErrorIs(t, g.Encrypt(&bytes.Buffer{}, []byte("x"), nil), crypto.ErrNoRecipients)
}

func TestGPGDecryptSurfacesGPGError(t *testing.T) {
	newGPGHome(t)
	g := crypto.NewGPG(t.TempDir(), "", nil)
	_, err := g.Decrypt(strings.NewReader("this is not openpgp data"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gpg", "the error keeps gpg's own diagnostics")
}

func TestGPGMissingBinary(t *testing.T) {
	g := crypto.NewGPG(t.TempDir(), "definitely-not-a-real-gpg", nil)
	assert.Error(t, g.Available())
	assert.Error(t, g.Encrypt(&bytes.Buffer{}, []byte("x"), []crypto.Recipient{"someone"}))
}

func TestGPGExtAndRecipientsFile(t *testing.T) {
	g := crypto.NewGPG(t.TempDir(), "", nil)
	assert.Equal(t, ".gpg", g.Ext())
	assert.Equal(t, ".gpg-id", g.RecipientsFile())
}

func TestGPGParseRecipients(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, ".gpg-id"), []byte("alice@example.com\nbob@example.com\n"), 0o600))

	got, err := crypto.NewGPG(root, "", nil).ParseRecipients(root)
	require.NoError(t, err)
	assert.Equal(t, []crypto.Recipient{"alice@example.com", "bob@example.com"}, got)
}
