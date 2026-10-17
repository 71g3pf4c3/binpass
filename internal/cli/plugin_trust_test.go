package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/71g3pf4c3/binpass/internal/config"
	"github.com/71g3pf4c3/binpass/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// plantStorePlugin writes a manifest-carrying plugin into the store's own
// plugin directory, which is exactly how a sync from a hostile remote
// delivers one: no install step, the directory simply appears.
func plantStorePlugin(t *testing.T, storeDir, name, manifest, script string) {
	t.Helper()
	dir := filepath.Join(storeDir, ".binpass", "plugins", name)
	require.NoError(t, os.MkdirAll(dir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, plugin.ManifestName), []byte(manifest), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "binpass-"+name), []byte(script), 0o700)) //nolint:gosec // a test stub that has to be runnable.
}

// trustTestApp returns an app that can see only the planted store plugin,
// with its lock file in a throwaway data directory.
func trustTestApp(t *testing.T) (*App, *bytes.Buffer, *bytes.Buffer, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the shebang convention is POSIX-only")
	}
	tmp := t.TempDir()
	// An empty PATH keeps the developer's own plugins out of discovery.
	t.Setenv("PATH", filepath.Join(tmp, "empty"))
	t.Setenv("BINPASS_DATA_DIR", filepath.Join(tmp, "data"))

	cfg := config.Default()
	cfg.Dir = filepath.Join(tmp, "store")
	app := NewApp(cfg)
	out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	app.Out, app.Err = out, errOut
	return app, out, errOut, cfg.Dir
}

// TestStorePlantedPluginNeedsApproval is the trust-on-first-use gate. The
// lock format existed and was tested, but nothing called it: a plugin
// committed to the shared store ran with the user's full authority the first
// time a command word matched its name, typo included.
func TestStorePlantedPluginNeedsApproval(t *testing.T) {
	app, out, errOut, storeDir := trustTestApp(t)
	const manifest = "name: greet\nversion: 1.0.0\napi: 1\nlevel: 1\n"
	plantStorePlugin(t, storeDir, "greet", manifest, "#!/bin/sh\necho ran\n")
	root := newRootCmd(app, "test", "none", "none")

	// The cases run in order against one plugin directory: approval is
	// trust on first use, so each state only exists after the previous one.
	for _, tc := range []struct {
		name    string
		before  func(t *testing.T)
		wantRun bool
		wantErr string
	}{
		{
			name:    "planted but never approved",
			wantErr: "binpass plugin trust greet",
		},
		{
			name:    "approved at this digest",
			before:  func(t *testing.T) { t.Helper(); require.NoError(t, app.runPluginTrust("greet")) },
			wantRun: true,
		},
		{
			name: "binary rewritten after approval",
			before: func(t *testing.T) {
				t.Helper()
				plantStorePlugin(t, storeDir, "greet", manifest, "#!/bin/sh\necho hijacked\n")
			},
			wantErr: "binpass plugin trust greet",
		},
		{
			name: "manifest widened after approval",
			before: func(t *testing.T) {
				t.Helper()
				// Re-approve the rewritten binary first, so the only thing
				// left to object to is the capability list.
				require.NoError(t, app.runPluginTrust("greet"))
				plantStorePlugin(t, storeDir, "greet",
					manifest+"capabilities:\n  read_paths: [\"**\"]\n  decrypt: true\n",
					"#!/bin/sh\necho hijacked\n")
			},
			wantErr: "binpass plugin trust greet",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.before != nil {
				tc.before(t)
			}
			out.Reset()
			errOut.Reset()

			handled, err := app.dispatchPlugin(context.Background(), root, []string{"greet"})
			require.True(t, handled, "the plugin claims the command either way")
			if tc.wantRun {
				require.NoError(t, err)
				assert.Contains(t, out.String(), "ran")
				return
			}
			require.Error(t, err)
			assert.ErrorContains(t, err, tc.wantErr, "the refusal must name how to approve it")
			assert.Empty(t, out.String(), "nothing may be executed before approval")
			assert.Contains(t, errOut.String(), "greet")
		})
	}
}

// TestPluginTrustShowsWhatIsBeingApproved covers the only consent the user
// is ever asked for: the summary has to state the consequence, and the
// digest has to be shown, or there is nothing to compare an update against.
func TestPluginTrustShowsWhatIsBeingApproved(t *testing.T) {
	app, out, errOut, storeDir := trustTestApp(t)
	plantStorePlugin(t, storeDir, "greet",
		"name: greet\nversion: 2.0.0\napi: 1\nlevel: 1\n"+
			"capabilities:\n  read_paths: [\"work/**\"]\n  decrypt: true\n",
		"#!/bin/sh\necho ran\n")

	require.NoError(t, app.runPluginTrust("greet"))

	got := out.String()
	assert.Contains(t, got, "CAN READ YOUR PASSWORDS IN PLAINTEXT")
	assert.Contains(t, got, "work/**")
	assert.Contains(t, got, "digest: ")
	assert.Contains(t, got, "Approved greet.")
	// A plugin from inside the store is a different proposition from one
	// the user installed by hand, and the difference has to be said.
	assert.Contains(t, errOut.String(), "inside the password store")

	// The grant is on disk, outside the store, so the next run finds it.
	lock, err := plugin.LoadLock(app.pluginLockPath())
	require.NoError(t, err)
	assert.Equal(t, []string{"greet"}, lock.Names())
	assert.NotContains(t, app.pluginLockPath(), storeDir)
}

// TestPluginTrustRefusesAnUnmanagedPlugin keeps the command honest: a bare
// executable on PATH carries no manifest, so there is nothing it could have
// been approved for.
func TestPluginTrustRefusesAnUnmanagedPlugin(t *testing.T) {
	app, _, _ := stubPlugin(t, "binpass-greet", "#!/bin/sh\necho ran\n")

	err := app.runPluginTrust("greet")
	require.Error(t, err)
	assert.ErrorContains(t, err, "carries no manifest")
}
