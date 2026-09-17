package cli

import (
	"bytes"
	"errors"
	"github.com/71g3pf4c3/binpass/internal/config"
	"io"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeSetup records what the OAuth flow did, standing in for rclone.
type fakeSetup struct {
	remotes []string
	listErr error
	authed  []string // "backend/name" pairs the flow tried to authorise
	authErr error
	sshell  bool // interactive?
}

func (f *fakeSetup) setup() rcloneSetup {
	return rcloneSetup{
		listRemotes: func() ([]string, error) { return f.remotes, f.listErr },
		auth: func(backend, name string) error {
			f.authed = append(f.authed, backend+"/"+name)
			return f.authErr
		},
		interactive: func() bool { return f.sshell },
	}
}

func TestEnsureRcloneAuth_AlreadyConfigured(t *testing.T) {
	f := &fakeSetup{remotes: []string{"mydrive:", "other:"}, sshell: true}
	var out, errOut bytes.Buffer

	require.NoError(t, f.setup().ensure("drive", "mydrive", &out, &errOut))

	assert.Empty(t, f.authed, "an authorised remote needs no new handshake")
	assert.Empty(t, out.String(), "nothing to tell the user")
}

func TestEnsureRcloneAuth_InteractiveRunsRclone(t *testing.T) {
	f := &fakeSetup{remotes: []string{"other:"}, sshell: true}
	var out, errOut bytes.Buffer

	require.NoError(t, f.setup().ensure("drive", "mydrive", &out, &errOut))

	require.Len(t, f.authed, 1)
	assert.Equal(t, "drive/mydrive", f.authed[0])
	assert.Contains(t, out.String(), "browser", "the user is told what is about to happen")
	assert.Contains(t, out.String(), "Token saved")
}

func TestEnsureRcloneAuth_AuthFailureIsReported(t *testing.T) {
	f := &fakeSetup{remotes: nil, sshell: true, authErr: errors.New("browser closed")}
	var out, errOut bytes.Buffer

	err := f.setup().ensure("yandex", "yd", &out, &errOut)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OAuth")
	assert.Contains(t, errOut.String(), "saved anyway", "the failure explains what happened to the remote")
}

func TestEnsureRcloneAuth_HeadlessPrintsTheDeviceFlow(t *testing.T) {
	f := &fakeSetup{remotes: nil, sshell: false}
	var out, errOut bytes.Buffer

	require.NoError(t, f.setup().ensure("drive", "mydrive", &out, &errOut))

	assert.Empty(t, f.authed, "no browser flow is started without a terminal")
	assert.Contains(t, out.String(), `rclone authorize "drive"`, "the command to run elsewhere is spelled out")
	assert.Contains(t, out.String(), "rclone config create mydrive drive token=", "so is the way to finish here")
}

func TestEnsureRcloneAuth_BrokenRcloneIsNotAnError(t *testing.T) {
	f := &fakeSetup{listErr: errors.New("exec: rclone: not found"), sshell: true}
	var out, errOut bytes.Buffer

	require.NoError(t, f.setup().ensure("drive", "mydrive", &out, &errOut))
	assert.Empty(t, f.authed, "nothing is attempted when rclone cannot even list remotes")
}

func TestRunRemoteAdd_GdriveDefaultsAndNormalisesURL(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("BINPASS_CONFIG", cfgPath)
	app := &App{Cfg: config.Default(), Out: io.Discard, Err: io.Discard}

	// No URL: the remote is named after itself.
	require.NoError(t, app.runRemoteAdd("gdrive", "mydrive"))
	assert.Equal(t, "mydrive:", app.Cfg.Remotes["mydrive"].URL)

	// A bare word: that remote at its root.
	require.NoError(t, app.runRemoteAdd("gdrive", "work", "teamdrive"))
	assert.Equal(t, "teamdrive:", app.Cfg.Remotes["work"].URL)

	// A full rclone path: kept as it is.
	require.NoError(t, app.runRemoteAdd("yandex", "yd", "yd:password-store"))
	assert.Equal(t, "yd:password-store", app.Cfg.Remotes["yd"].URL)
}
