package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/71g3pf4c3/binpass/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// configInTempDir points binpass's config file at a throwaway path, so that
// `remote add` never writes to the developer's own configuration.
func configInTempDir(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("BINPASS_CONFIG", path)
	return path
}

// TestRemoteAddKeepsTheResticPasswordOffDisk covers the key=value fields of
// `remote add`. A password handed over on the command line would be visible
// in ps while the command runs and would then sit in config.yaml in the
// clear, so the field is refused by name and the command that fetches it is
// accepted instead.
func TestRemoteAddKeepsTheResticPasswordOffDisk(t *testing.T) {
	const secretValue = "hunter2"

	for _, tc := range []struct {
		name    string
		field   string
		wantErr string
		wantCfg string
	}{
		{
			name:    "an inline password is refused by name",
			field:   "password=" + secretValue,
			wantErr: "password_command",
		},
		{
			name:    "the command that prints it is accepted",
			field:   "password_command=binpass show restic/backup",
			wantCfg: "password_command: binpass show restic/backup",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfgPath := configInTempDir(t)
			app := newTestApp(t)

			err := app.runRemoteAdd("restic", "backup", "/mnt/backup/binpass", tc.field)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr,
					"the refusal must name the field to use instead")
			} else {
				require.NoError(t, err)
			}

			data, readErr := os.ReadFile(cfgPath) //nolint:gosec // a path this test chose.
			if readErr != nil {
				require.True(t, os.IsNotExist(readErr), "unexpected error: %v", readErr)
				return
			}
			assert.NotContains(t, string(data), secretValue,
				"no password may be written to %s in the clear", cfgPath)
			if tc.wantCfg != "" {
				assert.Contains(t, string(data), tc.wantCfg)
			}
		})
	}
}

// TestRemoteListWarnsAboutAPlaintextPassword covers the remaining way a
// password gets into config.yaml: it is still a documented YAML field, so a
// hand-written config has one. Listing the remotes is where it becomes
// visible, so that is where the warning belongs — the file is 0600, but a
// backup of it, a copied $XDG_CONFIG_HOME or a config quoted in a bug report
// discloses the repository password.
func TestRemoteListWarnsAboutAPlaintextPassword(t *testing.T) {
	const secretValue = "hunter2"

	for _, tc := range []struct {
		name     string
		remote   config.RemoteConfig
		wantWarn bool
	}{
		{
			name:     "a plaintext password is called out",
			remote:   config.RemoteConfig{Type: "restic", URL: "/mnt/backup", Password: secretValue},
			wantWarn: true,
		},
		{
			name:     "a password command is not",
			remote:   config.RemoteConfig{Type: "restic", URL: "/mnt/backup", PasswordCommand: "binpass show restic/backup"},
			wantWarn: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			configInTempDir(t)
			app := newTestApp(t)
			app.Cfg.Remotes = map[string]config.RemoteConfig{"backup": tc.remote}

			require.NoError(t, app.runRemoteList())

			assert.Contains(t, app.out.String(), "backup", "the listing itself is unchanged")
			if tc.wantWarn {
				assert.Contains(t, app.errOut.String(), "plain text")
				assert.Contains(t, app.errOut.String(), "password_command")
			} else {
				assert.Empty(t, app.errOut.String())
			}
			assert.NotContains(t, app.out.String()+app.errOut.String(), secretValue,
				"the warning must not print the password it is warning about")
		})
	}
}
