package plugin_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/71g3pf4c3/binpass/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDiscoverConfinesExecToThePluginDirectory covers discovery, not just
// manifest parsing: a plugin whose exec resolves outside its own directory
// must not be found at all, or the manifest gets to nominate any executable
// already on disk and have binpass run it with the full plugin environment.
func TestDiscoverConfinesExecToThePluginDirectory(t *testing.T) {
	tests := map[string]struct {
		exec      string
		wantFound bool
	}{
		"the conventional name":   {"", true},
		"a file beside it":        {"helper.sh", true},
		"a file nested below it":  {"bin/helper.sh", true},
		"a parent-relative path":  {"../../outside.sh", false},
		"a traversal in the path": {"bin/../../../outside.sh", false},
		"an absolute path":        {"/bin/sh", false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			// The target exists, so only the containment check can be what
			// keeps it from being used.
			require.NoError(t, os.WriteFile(filepath.Join(root, "outside.sh"), []byte("#!/bin/sh\n"), 0o700)) //nolint:gosec // a test stub.

			dir := filepath.Join(root, "plugins", "demo")
			require.NoError(t, os.MkdirAll(filepath.Join(dir, "bin"), 0o700))
			manifest := "name: demo\nversion: 1.0.0\napi: 1\nlevel: 1\n"
			if tc.exec != "" {
				manifest += "exec: " + tc.exec + "\n"
			}
			require.NoError(t, os.WriteFile(filepath.Join(dir, plugin.ManifestName), []byte(manifest), 0o600))
			for _, bin := range []string{"binpass-demo", "helper.sh", "bin/helper.sh"} {
				require.NoError(t, os.WriteFile(filepath.Join(dir, bin), []byte("#!/bin/sh\n"), 0o700)) //nolint:gosec // a test stub.
			}

			src := plugin.Source{Dirs: []string{filepath.Join(root, "plugins")}}
			p, err := src.Find("demo")
			if !tc.wantFound {
				require.ErrorIs(t, err, plugin.ErrNotFound)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, dir, p.Dir)
			rel, err := filepath.Rel(dir, p.Path)
			require.NoError(t, err)
			assert.NotContains(t, rel, "..", "the executable must live inside the plugin directory")
		})
	}
}
