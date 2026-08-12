package tomb

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// Test helpers shared by the backends that drive external tools.
//
// Neither LUKS nor the sparse bundle can be exercised for real without the
// platform they belong to — cryptsetup needs root and a Linux kernel,
// hdiutil needs a Mac. Faking the runner is what makes the surrounding
// logic testable anywhere: which commands are issued, in what order, and
// what is cleaned up when one of them fails.

// storeWithState points the state file at a temporary directory, so that a
// test never touches the developer's own.
func storeWithState(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("BINPASS_DATA_DIR", filepath.Join(tmp, "state"))
	dir := filepath.Join(tmp, "store")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	return dir
}

// call records one invocation made through the fake runner.
type call struct {
	// name is the binary that would have been executed.
	name string
	// args are the arguments it would have received.
	args []string
	// stdin is what would have been written to it.
	stdin []byte
}

// fakeRunner records calls and replies from a script of canned results, so
// that the whole Init/Open/Close flow can be exercised without root, a loop
// device, or cryptsetup being installed.
type fakeRunner struct {
	// calls holds every invocation, in order.
	calls []call
	// fail maps a binary name to the failure it should produce.
	fail map[string]error
	// output maps a binary name to the output it should produce.
	output map[string][]byte
}

func (f *fakeRunner) run(name string, stdin []byte, args ...string) ([]byte, error) {
	cp := append([]byte(nil), stdin...)
	f.calls = append(f.calls, call{name: name, args: args, stdin: cp})
	if err, ok := f.fail[name]; ok {
		return f.output[name], err
	}
	return f.output[name], nil
}

// find returns the first call to a binary with the given first argument.
func (f *fakeRunner) find(name string, firstArg string) *call {
	for i := range f.calls {
		c := &f.calls[i]
		if c.name != name {
			continue
		}
		if firstArg == "" || (len(c.args) > 0 && c.args[0] == firstArg) {
			return c
		}
	}
	return nil
}

// names returns the binaries invoked, in order.
func (f *fakeRunner) names() []string {
	out := make([]string, 0, len(f.calls))
	for _, c := range f.calls {
		out = append(out, c.name)
	}
	return out
}
