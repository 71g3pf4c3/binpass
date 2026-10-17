package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/71g3pf4c3/binpass/internal/config"
	"github.com/71g3pf4c3/binpass/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// narrowGrant is what a plugin scoped to the work subtree carries: enough to
// be useful there, nothing at all outside it.
const narrowGrant = `{"read_paths":["work/*"],"write_paths":["work/*"],"decrypt":true}`

// restrictedApp returns a store holding one in-scope and one out-of-scope
// entry, in a process that looks exactly like a nested binpass invoked
// through BINPASS_BIN by a managed plugin with the given grant.
func restrictedApp(t *testing.T, grant string) *testApp {
	t.Helper()
	t.Setenv(plugin.EnvPluginName, "scoped")
	t.Setenv(plugin.EnvCapabilities, grant)
	app := newTestApp(t)
	app.set(t, "work/ci", "work-secret\n")
	app.set(t, "bank/savings", "bank-secret\n")
	return app
}

// TestCommandsRefuseOutOfScopeEntries covers every command that reaches the
// store without going through show/insert. Each of these used to call
// store.Get/Set/Move/Copy/Reencrypt with no capability check at all, which
// let a plugin granted work/* read or rewrite the whole store by picking a
// different subcommand.
func TestCommandsRefuseOutOfScopeEntries(t *testing.T) {
	ctx := context.Background()
	const conflict = "bank/savings.conflict-thinkpad-20260808T142233"

	for name, run := range map[string]func(*testApp) error{
		"otp": func(a *testApp) error {
			return a.runOTP(ctx, "bank/savings", false, false, false)
		},
		"otp --uri": func(a *testApp) error {
			return a.runOTP(ctx, "bank/savings", false, false, true)
		},
		"type": func(a *testApp) error {
			return a.runType(ctx, "bank/savings", "password", 0, "wtype")
		},
		"binary cat": func(a *testApp) error {
			return a.runBinaryCat("bank/savings.b64")
		},
		"binary sum": func(a *testApp) error {
			return a.runBinarySum("bank/savings.b64")
		},
		"binary copy": func(a *testApp) error {
			return a.runBinaryCopy("bank/planted.b64", filepath.Join(t.TempDir(), "absent"), true)
		},
		"binary move": func(a *testApp) error {
			return a.runBinaryMove("bank/planted.b64", filepath.Join(t.TempDir(), "absent"), true)
		},
		"conflicts diff": func(a *testApp) error {
			return a.runConflictsDiff(conflict, false)
		},
		"conflicts resolve": func(a *testApp) error {
			return a.runConflictsResolve(conflict, "remote")
		},
		"mv from an ungranted source": func(a *testApp) error {
			return a.runTransfer("bank/savings", "work/stolen", true, true)
		},
		"cp to an ungranted destination": func(a *testApp) error {
			return a.runTransfer("work/ci", "bank/planted", true, false)
		},
		"audit": func(a *testApp) error {
			return a.runAudit(ctx, "text", 1, true, nil)
		},
		"recrypt --dry-run": func(a *testApp) error {
			return a.runRecrypt("", config.BackendAge, true)
		},
		"init": func(a *testApp) error {
			return a.runInit("", []string{"age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"}, "")
		},
		"sops": func(a *testApp) error {
			cmd := newSopsCmd(a.App)
			cmd.SetArgs([]string{"ls", filepath.Join(t.TempDir(), "secrets.yaml")})
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			return cmd.Execute()
		},
	} {
		t.Run(name, func(t *testing.T) {
			app := restrictedApp(t, narrowGrant)
			err := run(app)
			require.Error(t, err, "the command must refuse an entry outside the grant")
			assert.ErrorIs(t, err, plugin.ErrDenied)
			// The out-of-scope secret must not have been decrypted on the
			// way to the refusal.
			assert.NotContains(t, app.out.String(), "bank-secret")
		})
	}
}

// TestCommandsAllowGrantedEntries is the other half of the guard: the checks
// must not turn a legitimate grant into a broken plugin.
func TestCommandsAllowGrantedEntries(t *testing.T) {
	app := restrictedApp(t, narrowGrant)

	require.NoError(t, app.runTransfer("work/ci", "work/ci2", true, false))
	s, err := app.Store()
	require.NoError(t, err)
	assert.True(t, s.Exists("work/ci2"))
}

// TestMenuOffersOnlyGrantedEntries pins that filtering happens before the
// picker is drawn: an entry the plugin may not read must never reach the
// chooser, where a single keystroke would turn it into a decrypt.
func TestMenuOffersOnlyGrantedEntries(t *testing.T) {
	app := restrictedApp(t, `{"read_paths":["nothing/*"]}`)

	err := app.runMenu(context.Background(), menuOpts{
		launcher: "auto", field: "password", prompt: "pass", sort: "name",
	})
	require.Error(t, err)
	assert.ErrorContains(t, err, "password store is empty",
		"a grant matching nothing must empty the picker, not expose the store")
}

// TestConflictsListFiltersUngrantedEntries keeps the conflict inventory to
// the subtree the plugin was granted; the names alone are store contents.
func TestConflictsListFiltersUngrantedEntries(t *testing.T) {
	app := restrictedApp(t, narrowGrant)
	app.set(t, "work/ci.conflict-thinkpad-20260808T142233", "work-local\n")
	app.set(t, "bank/savings.conflict-thinkpad-20260808T142233", "bank-local\n")

	require.NoError(t, app.runConflictsList())
	got := app.out.String()
	assert.Contains(t, got, "work/ci.conflict-thinkpad-20260808T142233")
	assert.NotContains(t, got, "bank/savings")
}

// TestExportStaysInsideTheGrant covers the batch plaintext dump: it used to
// walk the whole store with no check at all, which made it the cheapest way
// for a scoped plugin to read everything.
func TestExportStaysInsideTheGrant(t *testing.T) {
	for name, tc := range map[string]struct {
		grant     string
		wantEntry bool
	}{
		"read and decrypt inside the grant": {narrowGrant, true},
		"read without decrypt":              {`{"read_paths":["work/*"]}`, false},
	} {
		t.Run(name, func(t *testing.T) {
			app := restrictedApp(t, tc.grant)
			path := filepath.Join(t.TempDir(), "export.csv")

			require.NoError(t, app.runExport("csv", []string{path}))

			data, err := os.ReadFile(path) //nolint:gosec // a path this test chose.
			require.NoError(t, err)
			csv := string(data)
			assert.NotContains(t, csv, "bank", "an ungranted entry must not be exported")
			assert.NotContains(t, csv, "bank-secret")
			if tc.wantEntry {
				assert.Contains(t, csv, "work-secret")
			} else {
				assert.NotContains(t, csv, "work-secret",
					"reading a path is not permission to decrypt it")
			}
		})
	}
}

// TestGenerateInPlaceNeedsDecrypt covers the one write path that reads:
// --in-place keeps everything below the first line, which means decrypting
// the entry, so a grant that can write but not decrypt must not reach it.
func TestGenerateInPlaceNeedsDecrypt(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		grant   string
		inPlace bool
		wantErr bool
	}{
		"write-only grant, in place":  {`{"write_paths":["work/*"]}`, true, true},
		"write-only grant, overwrite": {`{"write_paths":["work/*"]}`, false, false},
		"write and decrypt, in place": {narrowGrant, true, false},
	} {
		t.Run(name, func(t *testing.T) {
			app := restrictedApp(t, tc.grant)

			err := app.runGenerate(ctx, "work/ci", 12, generateOpts{inPlace: tc.inPlace, force: true})
			if tc.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, plugin.ErrDenied)
				return
			}
			require.NoError(t, err)
		})
	}
}
