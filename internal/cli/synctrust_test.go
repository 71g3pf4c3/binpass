package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age/plugin"
	binplugin "github.com/71g3pf4c3/binpass/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReportStoreTrustWarnsOnRecipientChange covers the hostile-remote case:
// a remote that can write to the store adds a key to the recipients file, and
// without this check every later write silently encrypts to it as well.
func TestReportStoreTrustWarnsOnRecipientChange(t *testing.T) {
	tests := []struct {
		name string
		// setup runs before the first observation, so a case can choose the
		// baseline it is diffed against.
		setup func(t *testing.T, path, original string)
		// edit rewrites the store's recipients file between the two
		// observations; it is handed the original contents.
		edit func(t *testing.T, path, original string)
		want []string
		// absent are strings that must not appear in the warning.
		absent []string
	}{
		{
			name: "unchanged recipients say nothing",
			edit: func(*testing.T, string, string) {},
		},
		{
			name: "reordered lines are not a change",
			setup: func(t *testing.T, path, original string) {
				writeFile(t, path, original+newAgeRecipient(t)+"\n")
			},
			edit: func(t *testing.T, path, original string) {
				lines := strings.Split(strings.TrimSpace(readFile(t, path)), "\n")
				writeFile(t, path, lines[1]+"\n"+lines[0]+"\n")
			},
			absent: []string{"warning:"},
		},
		{
			name: "an added recipient is named",
			edit: func(t *testing.T, path, original string) {
				writeFile(t, path, original+"age1mallory\n")
			},
			want: []string{"warning: the recipients in .age-recipients changed", "+ age1mallory"},
		},
		{
			name: "a removed recipient is named",
			edit: func(t *testing.T, path, original string) {
				writeFile(t, path, "age1onlyone\n")
			},
			want: []string{"+ age1onlyone", "- age1"},
		},
		{
			name: "a new plugin recipient names the binary it will run",
			edit: func(t *testing.T, path, original string) {
				writeFile(t, path, original+plugin.EncodeRecipient("yubikey", []byte{1, 2, 3, 4})+"\n")
			},
			want: []string{"age plugin recipient: encrypting runs age-plugin-yubikey"},
		},
		{
			name: "a recipients file in a subdirectory is watched too",
			edit: func(t *testing.T, path, original string) {
				sub := filepath.Join(filepath.Dir(path), "work")
				require.NoError(t, os.MkdirAll(sub, 0o700))
				writeFile(t, filepath.Join(sub, ".age-recipients"), original)
			},
			// The subtree file is new, so first sight stays silent even
			// though the store as a whole is already known.
			absent: []string{"warning:"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := newTestApp(t)
			rcpFile := filepath.Join(app.dir, ".age-recipients")
			original, err := os.ReadFile(rcpFile)
			require.NoError(t, err)
			if tt.setup != nil {
				tt.setup(t, rcpFile, string(original))
			}

			// First sight records the store without saying anything: there
			// is no baseline to compare a fresh store against.
			app.reportStoreTrust(app.dir)
			require.Empty(t, app.errOut.String(), "the first observation must be silent")
			require.FileExists(t, filepath.Join(app.stateDir, trustStateName))

			tt.edit(t, rcpFile, string(original))
			app.reportStoreTrust(app.dir)

			got := app.errOut.String()
			for _, want := range tt.want {
				assert.Contains(t, got, want)
			}
			for _, absent := range tt.absent {
				assert.NotContains(t, got, absent)
			}
			if len(tt.want) == 0 && len(tt.absent) == 0 {
				assert.Empty(t, got)
			}
		})
	}
}

// TestReportStoreTrustWarnsOnlyOnce checks that a change the user has already
// been told about does not reappear on every later sync.
func TestReportStoreTrustWarnsOnlyOnce(t *testing.T) {
	app := newTestApp(t)
	rcpFile := filepath.Join(app.dir, ".age-recipients")
	original, err := os.ReadFile(rcpFile)
	require.NoError(t, err)

	app.reportStoreTrust(app.dir)
	writeFile(t, rcpFile, string(original)+"age1mallory\n")

	app.reportStoreTrust(app.dir)
	require.Contains(t, app.errOut.String(), "+ age1mallory")

	app.errOut.Reset()
	app.reportStoreTrust(app.dir)
	assert.Empty(t, app.errOut.String(), "the new set is the baseline once it has been reported")
}

// TestReportStoreTrustWarnsOnStorePluginChange covers detectability of a
// store-planted plugin: .binpass/plugins travels with every sync, and a
// plugin there provides a subcommand that runs before the command line is
// even parsed. Nothing used to say that one had appeared.
func TestReportStoreTrustWarnsOnStorePluginChange(t *testing.T) {
	app := newTestApp(t)

	app.reportStoreTrust(app.dir)
	require.Empty(t, app.errOut.String())

	dir := filepath.Join(binplugin.StorePluginsDir(app.dir), "evil")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	writeFile(t, filepath.Join(dir, binplugin.ManifestName), "name: evil\nversion: 1.0.0\napi: 1\n")
	writeFile(t, filepath.Join(dir, "binpass-evil"), "#!/bin/sh\n")

	app.reportStoreTrust(app.dir)
	got := app.errOut.String()
	assert.Contains(t, got, "warning: the plugins inside the store changed")
	assert.Contains(t, got, "+ evil (new)")

	// A replaced executable is the same threat with the name already known.
	app.errOut.Reset()
	writeFile(t, filepath.Join(dir, "binpass-evil"), "#!/bin/sh\nevil\n")
	app.reportStoreTrust(app.dir)
	assert.Contains(t, app.errOut.String(), "~ evil (manifest or executable replaced)")

	app.errOut.Reset()
	app.reportStoreTrust(app.dir)
	assert.Empty(t, app.errOut.String(), "a plugin already reported is the new baseline")
}

// newAgeRecipient returns a throwaway age recipient string.
func newAgeRecipient(t *testing.T) string {
	t.Helper()
	return plugin.EncodeRecipient("test", []byte{9, 9, 9, 9})
}

// readFile reads a store file for a test fixture.
func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(data)
}

// writeFile writes a store file for a test fixture.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}
