package cli

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestProgramNameFollowsArgv0 covers the `pass` shim: installing binpass as
// `pass` is a supported way to adopt it, and the program has to answer to the
// name it was invoked under. Completions matter most — cobra names its
// generated functions after this, so a script generated as "binpass" and
// installed as "pass" completes a command that is not there.
func TestProgramNameFollowsArgv0(t *testing.T) {
	orig := os.Args
	t.Cleanup(func() { os.Args = orig })

	for name, tc := range map[string]struct {
		argv0 string
		want  string
	}{
		"plain binpass":     {"binpass", "binpass"},
		"absolute path":     {"/nix/store/abc-binpass-0.1.0/bin/binpass", "binpass"},
		"installed as pass": {"/run/current-system/sw/bin/pass", "pass"},
		"windows binpass":   {`C:\Program Files\binpass\binpass.exe`, "binpass"},
		"windows pass":      {`C:\tools\pass.exe`, "pass"},
		// Anything else falls back rather than echoing argv[0]: a symlink
		// named "--help" must not get to choose what the help text says.
		"unexpected name": {"/tmp/--help", "binpass"},
		"empty":           {"", "binpass"},
	} {
		t.Run(name, func(t *testing.T) {
			os.Args = []string{tc.argv0}
			assert.Equal(t, tc.want, programName())
		})
	}
}
