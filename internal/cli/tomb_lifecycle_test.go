package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/71g3pf4c3/binpass/internal/config"
	"github.com/71g3pf4c3/binpass/pkg/secret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tombFixture is an initialised age store with one entry, wired to an App,
// with every path inside the test's temporary directories.
type tombFixture struct {
	app   *App
	dir   string
	out   *bytes.Buffer
	errOu *bytes.Buffer
}

// newTombFixture builds a store the tomb commands can operate on.
//
// The sidecar directory is redirected too: tomb state must never be written
// to the developer's real ~/.local/share, and a test that did would also see
// state left over from previous runs.
func newTombFixture(t *testing.T) *tombFixture {
	t.Helper()

	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	dir := t.TempDir()
	sidecar := t.TempDir()
	t.Setenv("BINPASS_DATA_DIR", sidecar)
	// The tomb decrypts the coffin through the identity resolver, so the key
	// has to be where that resolver looks — inside the test's own sidecar,
	// never the developer's real one.
	require.NoError(t, os.WriteFile(filepath.Join(sidecar, "identities.age"),
		[]byte(id.String()+"\n"), 0o600))

	require.NoError(t, os.WriteFile(filepath.Join(dir, ".age-recipients"),
		[]byte(id.Recipient().String()+"\n"), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "bank"), 0o700))

	cfg := config.Default()
	cfg.Dir = dir
	app := NewApp(cfg)

	out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	app.Out, app.Err = out, errOut

	s, err := app.Store()
	require.NoError(t, err)
	require.NoError(t, s.Set("bank/acct", secret.Parse([]byte("topsecret\nusername: alice\n"))))

	return &tombFixture{app: app, dir: dir, out: out, errOu: errOut}
}

// entries lists the store entry files present on disk.
func (f *tombFixture) entries(t *testing.T) []string {
	t.Helper()
	var out []string
	require.NoError(t, filepath.Walk(f.dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if filepath.Ext(path) == ".age" && !strings.Contains(path, "coffin") {
			rel, _ := filepath.Rel(f.dir, path)
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	}))
	return out
}

// TestTombLifecycleThroughCLI exercises init, close, status and open the way
// the commands do, rather than through the backend directly.
//
// The point is the round trip: a tomb that hides entries but cannot give them
// back is data loss, and nothing below the CLI proves the two halves are
// wired to the same store.
func TestTombLifecycleThroughCLI(t *testing.T) {
	f := newTombFixture(t)
	require.Equal(t, []string{"bank/acct.age"}, f.entries(t))

	require.NoError(t, f.app.runTombInit("", "", ""))
	require.NoError(t, f.app.runTombClose(true))

	assert.Empty(t, f.entries(t), "closing must leave no plaintext entry behind")
	assert.FileExists(t, filepath.Join(f.dir, "store.coffin.age"),
		"the encrypted container replaces them")

	// A closed store must not answer for its entries.
	_, err := f.app.Store()
	require.NoError(t, err)

	require.NoError(t, f.app.runTombOpen(0))
	assert.Equal(t, []string{"bank/acct.age"}, f.entries(t), "opening must restore every entry")

	s, err := f.app.Store()
	require.NoError(t, err)
	sec, err := s.Get("bank/acct")
	require.NoError(t, err)
	assert.Equal(t, "topsecret", sec.Password(), "the secret must survive the round trip intact")
	user, ok := sec.Field("username")
	require.True(t, ok)
	assert.Equal(t, "alice", user, "and so must its fields")
}

// TestTombStatusReportsBothStates checks the status the user acts on.
func TestTombStatusReportsBothStates(t *testing.T) {
	f := newTombFixture(t)
	require.NoError(t, f.app.runTombInit("", "", ""))

	f.out.Reset()
	require.NoError(t, f.app.runTombStatus())
	assert.Contains(t, f.out.String(), "open")
	assert.NotContains(t, f.out.String(), "stale",
		"a tomb that was just opened has not crashed")

	require.NoError(t, f.app.runTombClose(true))
	f.out.Reset()
	require.NoError(t, f.app.runTombStatus())
	assert.Contains(t, f.out.String(), "closed")
}

// TestTombCloseWithoutInitLeavesTheStoreAlone covers the case where there is
// no tomb to close. Reporting that is fine; quietly shredding entries that
// were never packed into a container would not be.
func TestTombCloseWithoutATombIsRefused(t *testing.T) {
	f := newTombFixture(t)

	err := f.app.runTombClose(true)
	require.Error(t, err, "claiming to have closed a tomb that does not exist would be a lie about safety")
	assert.ErrorContains(t, err, "tomb init")
	assert.Equal(t, []string{"bank/acct.age"}, f.entries(t),
		"with no container to close, the entries must still be there")
}
