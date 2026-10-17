package plugin_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/71g3pf4c3/binpass/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// installStorePlugin writes a plugin into a store's .binpass/plugins, the way
// a sync would deliver one.
func installStorePlugin(t *testing.T, storeDir, name, version, body string) {
	t.Helper()
	dir := filepath.Join(plugin.StorePluginsDir(storeDir), name)
	require.NoError(t, os.MkdirAll(dir, 0o700))
	manifest := "name: " + name + "\nversion: " + version + "\napi: 1\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, plugin.ManifestName), []byte(manifest), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "binpass-"+name), []byte(body), 0o700))
}

// TestDiffStorePlugins covers the detectability gap behind a store-planted
// plugin: the store's plugin directory syncs with the store, dispatch happens
// before cobra sees the command line, and nothing ever compared the directory
// against what was there before.
func TestDiffStorePlugins(t *testing.T) {
	tests := []struct {
		name string
		// before sets up the store as the last sync left it.
		before func(t *testing.T, storeDir string)
		// after mutates it the way an incoming sync would.
		after func(t *testing.T, storeDir string)
		want  plugin.StorePluginDiff
	}{
		{
			name:   "an empty store has no plugins",
			before: func(*testing.T, string) {},
			after:  func(*testing.T, string) {},
		},
		{
			name:   "an unchanged plugin is not reported",
			before: func(t *testing.T, d string) { installStorePlugin(t, d, "demo", "1.0.0", "#!/bin/sh\n") },
			after:  func(*testing.T, string) {},
		},
		{
			name:   "a new plugin is reported",
			before: func(*testing.T, string) {},
			after:  func(t *testing.T, d string) { installStorePlugin(t, d, "demo", "1.0.0", "#!/bin/sh\n") },
			want:   plugin.StorePluginDiff{Added: []string{"demo"}},
		},
		{
			name:   "a swapped executable is reported",
			before: func(t *testing.T, d string) { installStorePlugin(t, d, "demo", "1.0.0", "#!/bin/sh\n") },
			after:  func(t *testing.T, d string) { installStorePlugin(t, d, "demo", "1.0.0", "#!/bin/sh\nevil\n") },
			want:   plugin.StorePluginDiff{Changed: []string{"demo"}},
		},
		{
			name:   "a rewritten manifest is reported",
			before: func(t *testing.T, d string) { installStorePlugin(t, d, "demo", "1.0.0", "#!/bin/sh\n") },
			after:  func(t *testing.T, d string) { installStorePlugin(t, d, "demo", "2.0.0", "#!/bin/sh\n") },
			want:   plugin.StorePluginDiff{Changed: []string{"demo"}},
		},
		{
			name:   "a removed plugin is reported",
			before: func(t *testing.T, d string) { installStorePlugin(t, d, "demo", "1.0.0", "#!/bin/sh\n") },
			after: func(t *testing.T, d string) {
				require.NoError(t, os.RemoveAll(filepath.Join(plugin.StorePluginsDir(d), "demo")))
			},
			want: plugin.StorePluginDiff{Removed: []string{"demo"}},
		},
		{
			name:   "every change is reported, in a stable order",
			before: func(t *testing.T, d string) { installStorePlugin(t, d, "gone", "1.0.0", "#!/bin/sh\n") },
			after: func(t *testing.T, d string) {
				require.NoError(t, os.RemoveAll(filepath.Join(plugin.StorePluginsDir(d), "gone")))
				installStorePlugin(t, d, "beta", "1.0.0", "#!/bin/sh\n")
				installStorePlugin(t, d, "alpha", "1.0.0", "#!/bin/sh\n")
			},
			want: plugin.StorePluginDiff{Added: []string{"alpha", "beta"}, Removed: []string{"gone"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storeDir := t.TempDir()
			tt.before(t, storeDir)
			before := plugin.SnapshotStorePlugins(storeDir)

			tt.after(t, storeDir)
			got := plugin.DiffStorePlugins(before, plugin.SnapshotStorePlugins(storeDir))

			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.want.Empty(), got.Empty())
		})
	}
}

// TestSnapshotStorePluginsIgnoresEverythingElse checks that the snapshot is
// about the store only: a plugin the user installed themselves is not what
// this warning is for, and an absent directory is not an error.
func TestSnapshotStorePluginsIgnoresEverythingElse(t *testing.T) {
	assert.Empty(t, plugin.SnapshotStorePlugins(t.TempDir()))
	assert.Empty(t, plugin.SnapshotStorePlugins(""))
	assert.Equal(t, "", plugin.StorePluginsDir(""))

	storeDir := t.TempDir()
	installStorePlugin(t, storeDir, "demo", "1.0.0", "#!/bin/sh\n")
	snap := plugin.SnapshotStorePlugins(storeDir)
	require.Len(t, snap, 1)
	assert.NotEmpty(t, snap["demo"], "a plugin must digest to something")
}
