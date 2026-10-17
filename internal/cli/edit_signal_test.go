package cli

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The environment the child half of the signal test is driven by.
const (
	// editChildEnv marks the child process that runs the real edit flow.
	editChildEnv = "BINPASS_TEST_EDIT_CHILD"
	// editMarkerEnv names the file the fake editor reports its argument in.
	editMarkerEnv = "BINPASS_TEST_EDIT_MARKER"
)

// TestRunEditInterruptChild is the child half of
// TestRunEditShredsTheTempFileOnSignal. It runs the genuine edit flow with a
// fake $EDITOR that reports the temporary file and then sleeps, so the parent
// can signal the process while the plaintext is on disk.
func TestRunEditInterruptChild(t *testing.T) {
	if os.Getenv(editChildEnv) == "" {
		t.Skip("child half of TestRunEditShredsTheTempFileOnSignal")
	}
	app := newTestApp(t)
	app.set(t, "entry", "hunter2\n")
	_ = app.runEdit(context.Background(), "entry")
}

// TestRunEditShredsTheTempFileOnSignal covers the exit path that is the
// normal way out of an edit: Ctrl-C reaches binpass as well as $EDITOR,
// because both are in the terminal's foreground process group. Until the
// signal was handled, the process died before any defer ran and the
// decrypted entry stayed in the temporary file with nothing left to remove
// it.
func TestRunEditShredsTheTempFileOnSignal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX signals cannot be delivered to another process on Windows")
	}

	for _, tc := range []struct {
		name string
		sig  os.Signal
		code int
	}{
		{name: "SIGINT, as Ctrl-C in the editor delivers it", sig: os.Interrupt, code: 130},
		{name: "SIGTERM, as a session teardown delivers it", sig: syscall.SIGTERM, code: 143},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			marker := filepath.Join(dir, "editing")
			editor := filepath.Join(dir, "editor.sh")
			// The editor reports the file it was handed and then stays alive,
			// which is the window the signal has to be survived in.
			require.NoError(t, os.WriteFile(editor,
				[]byte("#!/bin/sh\nprintf '%s' \"$1\" > \"$"+editMarkerEnv+"\"\nsleep 5\n"), 0o700)) //nolint:gosec // a fake editor in a temp dir.

			logPath := filepath.Join(dir, "child.log")
			log, err := os.Create(logPath) //nolint:gosec // a path this test chose.
			require.NoError(t, err)
			defer func() { _ = log.Close() }()

			cmd := exec.Command(os.Args[0], "-test.run=^TestRunEditInterruptChild$") //nolint:gosec // this test binary.
			cmd.Env = append(os.Environ(),
				editChildEnv+"=1",
				editMarkerEnv+"="+marker,
				"EDITOR="+editor,
			)
			// A file rather than a buffer: the sleeping editor inherits the
			// child's standard streams, so a pipe would keep Wait blocked
			// until that grandchild exited too.
			cmd.Stdout, cmd.Stderr = log, log
			require.NoError(t, cmd.Start())
			t.Cleanup(func() { _ = cmd.Process.Kill() })

			tmp := waitForEditTempFile(t, marker, logPath)
			// If an assertion below fails, the plaintext must still not be
			// left lying around by the test itself.
			t.Cleanup(func() { _ = os.Remove(tmp) })

			plaintext, err := os.ReadFile(tmp) //nolint:gosec // the path the child just reported.
			require.NoError(t, err)
			require.Equal(t, "hunter2\n", string(plaintext),
				"the test is only meaningful while the decrypted entry is really on disk")

			require.NoError(t, cmd.Process.Signal(tc.sig))

			var exitErr *exec.ExitError
			require.ErrorAs(t, cmd.Wait(), &exitErr)
			assert.Equal(t, tc.code, exitErr.ExitCode(),
				"a signalled edit must report the signal, not success")
			assert.NoFileExists(t, tmp,
				"the decrypted entry must not survive the signal: %s", childLog(logPath))
		})
	}
}

// waitForEditTempFile returns the temporary file path the fake editor
// reported, waiting for the child to get that far.
func waitForEditTempFile(t *testing.T, marker, logPath string) string {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(marker); err == nil && len(data) > 0 { //nolint:gosec // a path this test chose.
			return strings.TrimSpace(string(data))
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the child never reached $EDITOR: %s", childLog(logPath))
	return ""
}

// childLog returns whatever the child reported, for a failure message.
func childLog(path string) string {
	data, err := os.ReadFile(path) //nolint:gosec // a path this test chose.
	if err != nil {
		return err.Error()
	}
	return string(data)
}
