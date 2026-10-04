package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/71g3pf4c3/binpass/internal/config"
	"github.com/71g3pf4c3/binpass/pkg/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countExt reports how many files under root carry ext, which is how the
// tests tell a reencrypted store from a rewritten-in-place one.
func countExt(t *testing.T, root, ext string) int {
	t.Helper()
	n := 0
	err := filepath.WalkDir(root, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ext) {
			n++
		}
		return nil
	})
	require.NoError(t, err)
	return n
}

// newGpgTestApp builds a store whose default backend is GPG, backed by a
// throwaway keyring, so a migration to age has something to migrate. The
// test skips when gpg is not on PATH: the migration itself is what needs
// the real binary, and a stub would prove nothing about it.
func newGpgTestApp(t *testing.T) *testApp {
	t.Helper()
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not on PATH: cannot build the throwaway keyring")
	}
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "store")
	require.NoError(t, os.MkdirAll(dir, 0o700))

	home := filepath.Join(tmp, "gnupg")
	require.NoError(t, os.MkdirAll(home, 0o700))
	t.Setenv("GNUPGHOME", home)

	const uid = "recrypt@example.invalid"
	gen := exec.Command("gpg", "--batch", "--passphrase", "", "--quick-generate-key", uid, "default", "default", "never")
	if out, err := gen.CombinedOutput(); err != nil {
		t.Skipf("cannot generate a test key: %v: %s", err, out)
	}

	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	keyFile := filepath.Join(tmp, "identity.key")
	require.NoError(t, os.WriteFile(keyFile, []byte(id.String()+"\n"), 0o600))

	cfg := config.Default()
	cfg.Dir = dir
	cfg.Identity = keyFile
	cfg.Default = config.BackendGPG

	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}
	app := &App{Cfg: cfg, Out: out, Err: errOut, In: strings.NewReader("")}

	s, err := app.Store()
	require.NoError(t, err)
	require.NoError(t, s.Init("", []crypto.Recipient{crypto.Recipient(uid)}))

	return &testApp{App: app, out: out, errOut: errOut, dir: dir, stateDir: filepath.Join(tmp, "state")}
}

// ageRecipientsFile writes the age recipients file by hand: the app's
// default backend is GPG, so Init would write .gpg-id instead.
func ageRecipientsFile(t *testing.T, dir, recipient string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".age-recipients"), []byte(recipient+"\n"), 0o644))
}

func TestRecryptDryRunReportsAndChangesNothing(t *testing.T) {
	app := newTestApp(t)
	app.set(t, "alpha", "secret-alpha\n")
	app.set(t, "web/beta", "secret-beta\n")

	require.NoError(t, app.runRecrypt("", config.BackendAge, true))

	assert.Contains(t, app.out.String(), "Would reencrypt 2 entries for the age backend (0 changing format)")
	// Nothing was rewritten: the entries still decrypt, and no second
	// format appeared.
	assert.Equal(t, 2, countExt(t, app.dir, ".age"))
	assert.Equal(t, 0, countExt(t, app.dir, ".gpg"))
	s, err := app.Store()
	require.NoError(t, err)
	sec, err := s.Get("web/beta")
	require.NoError(t, err)
	assert.Equal(t, "secret-beta\n", string(sec.Bytes()))
}

func TestRecryptAgeRefreshKeepsEntries(t *testing.T) {
	app := newTestApp(t)
	app.set(t, "alpha", "secret-alpha\n")

	require.NoError(t, app.runRecrypt("", config.BackendAge, false))

	assert.Contains(t, app.out.String(), "Reencrypted 1 entries for the age backend (0 changed format)")
	assert.Equal(t, 1, countExt(t, app.dir, ".age"))
	s, err := app.Store()
	require.NoError(t, err)
	sec, err := s.Get("alpha")
	require.NoError(t, err)
	assert.Equal(t, "secret-alpha\n", string(sec.Bytes()))
}

func TestRecryptWithoutRecipientsFileRefuses(t *testing.T) {
	app := newTestApp(t)
	app.set(t, "alpha", "secret-alpha\n")
	require.NoError(t, os.Remove(filepath.Join(app.dir, ".age-recipients")))

	err := app.runRecrypt("", config.BackendAge, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "binpass init")
	// The entry was not touched on the way to the refusal.
	s, err := app.Store()
	require.NoError(t, err)
	sec, err := s.Get("alpha")
	require.NoError(t, err)
	assert.Equal(t, "secret-alpha\n", string(sec.Bytes()))
}

func TestRecryptGpgToAgeMigrates(t *testing.T) {
	app := newGpgTestApp(t)
	app.set(t, "legacy", "secret-legacy\n")
	require.Equal(t, 1, countExt(t, app.dir, ".gpg"))

	// The age identity backing the app's config is what recrypt will read
	// .age-recipients from and later decrypt with.
	id := ageIdentity(t, app.Cfg.Identity)
	ageRecipientsFile(t, app.dir, id.Recipient().String())

	require.NoError(t, app.runRecrypt("", config.BackendAge, false))

	assert.Contains(t, app.out.String(), "Reencrypted 1 entries for the age backend (1 changed format)")
	assert.Equal(t, 0, countExt(t, app.dir, ".gpg"))
	assert.Equal(t, 1, countExt(t, app.dir, ".age"))
	s, err := app.Store()
	require.NoError(t, err)
	sec, err := s.Get("legacy")
	require.NoError(t, err)
	assert.Equal(t, "secret-legacy\n", string(sec.Bytes()))
}

func TestInitAgeMigratesExistingGpgStore(t *testing.T) {
	app := newGpgTestApp(t)
	app.set(t, "legacy", "secret-legacy\n")
	require.Equal(t, 1, countExt(t, app.dir, ".gpg"))

	id := ageIdentity(t, app.Cfg.Identity)

	// The CLI flow sets the backend flag before the store is built, which
	// is why Init writes .age-recipients there; the pre-built gpg store
	// above cannot be reused for that, so the command runs on a second
	// app over the same directory and identity.
	cfg := app.Cfg
	cfg.Default = config.BackendAge
	migrate := &App{Cfg: cfg, Out: &bytes.Buffer{}, Err: &bytes.Buffer{}, In: strings.NewReader("")}
	require.NoError(t, migrate.runInit("", []string{id.Recipient().String()}, config.BackendAge))

	assert.Equal(t, 0, countExt(t, app.dir, ".gpg"))
	assert.Equal(t, 1, countExt(t, app.dir, ".age"))
	s, err := migrate.Store()
	require.NoError(t, err)
	sec, err := s.Get("legacy")
	require.NoError(t, err)
	assert.Equal(t, "secret-legacy\n", string(sec.Bytes()))
}

// ageIdentity loads an identity file the helper itself wrote, which keeps
// the test independent of how the resolver names its sources.
func ageIdentity(t *testing.T, path string) *age.X25519Identity {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	id, err := age.ParseX25519Identity(strings.TrimSpace(string(raw)))
	require.NoError(t, err)
	return id
}
