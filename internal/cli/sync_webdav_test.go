package cli

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/71g3pf4c3/binpass/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startWebDAV serves a directory over WebDAV with a real rclone, the way a
// Nextcloud or an Apache would, and returns the rclone remote name
// addressing it. Skipped without rclone on PATH, as the transport tests are.
func startWebDAV(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("rclone"); err != nil {
		t.Skip("rclone not on PATH")
	}
	root := t.TempDir()

	port, err := freeTCPPort()
	require.NoError(t, err)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

	proc := exec.Command("rclone", "serve", "webdav", root, "--addr", addr) //nolint:gosec // fixed program, local test server.
	require.NoError(t, proc.Start())
	t.Cleanup(func() {
		_ = proc.Process.Kill()
		_ = proc.Wait()
	})

	// rclone builds the remote from the environment, exactly the way CI
	// configures it — no config file a test would have to clean up. The
	// remote name in the variable is upper-cased, as rclone requires.
	name := "testwd" + strconv.Itoa(port)
	env := strings.ToUpper(name)
	t.Setenv("RCLONE_CONFIG_"+env+"_TYPE", "webdav")
	t.Setenv("RCLONE_CONFIG_"+env+"_URL", "http://"+addr)
	t.Setenv("RCLONE_CONFIG_"+env+"_VENDOR", "other")

	// Readiness: rclone answers directory listings, or nothing the sync
	// does can work. A plain TCP dial says the port is bound; lsjson says
	// the WebDAV layer is actually serving.
	deadline := time.Now().Add(10 * time.Second)
	for {
		out, err := exec.Command("rclone", "lsjson", name+":").Output() //nolint:gosec // fixed program, fixed argument.
		if err == nil && len(out) > 0 {                                 // an empty listing is "[]" — still an answer
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("rclone serve webdav did not come up on %s", addr)
		}
		time.Sleep(100 * time.Millisecond)
	}
	return name + ":"
}

// freeTCPPort asks the kernel for a port nothing is using.
func freeTCPPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// TestWebDAVSync_E2E drives the sync engine through the rclone transport
// against a real WebDAV server: two devices, a push, a pull, and an
// edit-versus-edit conflict — the flow the advisory lock serialises and the
// weak-rev conditional writes guard.
func TestWebDAVSync_E2E(t *testing.T) {
	remote := startWebDAV(t)

	appA := newTestApp(t)
	appB := newTestApp(t)
	// Device B reads what device A encrypts; the store resolves the
	// identity lazily, so swapping the config after construction is enough.
	appB.Cfg.Identity = appA.Cfg.Identity

	appA.Cfg.Remotes = map[string]config.RemoteConfig{"backup": {Type: "webdav", URL: remote}}
	appB.Cfg.Remotes = map[string]config.RemoteConfig{"backup": {Type: "webdav", URL: remote}}

	ctx := context.Background()

	// A creates and pushes.
	appA.activate(t)
	appA.set(t, "github.com/alice", "hunter2\n")
	require.NoError(t, appA.runSync(ctx, "backup", false))

	// B pulls and has the entry.
	appB.activate(t)
	require.NoError(t, appB.runSync(ctx, "backup", false))
	bs, err := appB.Store()
	require.NoError(t, err)
	sec, err := bs.Get("github.com/alice")
	require.NoError(t, err)
	assert.Equal(t, "hunter2", sec.Password())

	// Both devices edit the same entry offline.
	appA.set(t, "shared/entry", "version-from-a\n")
	appB.set(t, "shared/entry", "version-from-b\n")

	// A syncs its edit first.
	appA.activate(t)
	require.NoError(t, appA.runSync(ctx, "backup", false))

	// B's edit now conflicts; the sync must detect it and keep both.
	appB.activate(t)
	appB.out.Reset()
	require.NoError(t, appB.runSync(ctx, "backup", false))

	assert.Contains(t, appB.out.String(), "conflict", "the sync reports the conflict")
	matches, err := filepath.Glob(filepath.Join(appB.dir, "shared", "entry.conflict-*.age"))
	require.NoError(t, err)
	require.Len(t, matches, 1, "device B keeps its local version as a conflict file")

	sec, err = bs.Get("shared/entry")
	require.NoError(t, err)
	assert.Equal(t, "version-from-a", sec.Password(), "the remote version takes the plain path")

	// The advisory lock must not leak into the store as an entry.
	entries, err := bs.List("")
	require.NoError(t, err)
	for _, e := range entries {
		assert.NotContains(t, e, ".binpass.lock",
			fmt.Sprintf("the lock file is transport state, not an entry (store has %v)", entries))
	}
}
