package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExportFileIsNotWorldReadable pins the permissions of the one file
// binpass writes that holds every password in plaintext. os.Create left it
// at 0666 minus the umask — typically 0644 — on a shared host.
func TestExportFileIsNotWorldReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits")
	}
	for name, tc := range map[string]struct{ pre os.FileMode }{
		"a new file":                  {0},
		"an existing permissive file": {0o644},
	} {
		t.Run(name, func(t *testing.T) {
			app := newTestApp(t)
			app.set(t, "alice", "hunter2\n")
			path := filepath.Join(t.TempDir(), "export.csv")
			if tc.pre != 0 {
				require.NoError(t, os.WriteFile(path, []byte("stale\n"), tc.pre))
			}

			require.NoError(t, app.runExport("csv", []string{path}))

			fi, err := os.Stat(path)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm(),
				"a plaintext password dump must be readable by its owner only")
			data, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Contains(t, string(data), "hunter2")
			assert.NotContains(t, string(data), "stale", "the file is truncated, not appended to")
		})
	}
}
