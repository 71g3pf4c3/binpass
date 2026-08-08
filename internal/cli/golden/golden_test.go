// Package golden compares binpass against the real pass(1) binary.
//
// Both programs are pointed at an identical store and given the same command;
// stdout, stderr, exit status and the resulting tree must agree. This is what
// turns "compatible with pass" into a claim the build can verify.
package golden

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// binpassBin is the path of the binary under test, built once per run.
var binpassBin string

// TestMain builds binpass and checks that the reference tools are present.
func TestMain(m *testing.M) {
	if _, err := exec.LookPath("pass"); err != nil {
		// Without the reference implementation these tests prove nothing.
		os.Exit(0)
	}
	dir, err := os.MkdirTemp("", "binpass-build-*")
	if err != nil {
		panic(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	binpassBin = filepath.Join(dir, "binpass")
	build := exec.Command("go", "build", "-o", binpassBin, "github.com/71g3pf4c3/binpass/cmd/binpass")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		panic(string(out))
	}
	os.Exit(m.Run())
}

// world is a pair of identical stores, one driven by pass and one by binpass.
type world struct {
	// gnupgHome is the throwaway keyring both stores encrypt to.
	gnupgHome string
	// recipient is the GPG key ID of that keyring.
	recipient string
	// passDir is the store pass operates on.
	passDir string
	// binpassDir is the store binpass operates on.
	binpassDir string
}

// newWorld creates a keyring and two initialised, identical stores.
func newWorld(t *testing.T) *world {
	t.Helper()

	// gpg-agent's socket path is length-limited, so the keyring cannot live
	// under a long TMPDIR-derived path.
	home, err := os.MkdirTemp("", "bp-gpg-*")
	require.NoError(t, err)
	require.NoError(t, os.Chmod(home, 0o700))
	t.Cleanup(func() {
		_ = exec.Command("gpgconf", "--homedir", home, "--kill", "all").Run()
		_ = os.RemoveAll(home)
	})

	const uid = "golden@example.invalid"
	gen := exec.Command("gpg", "--batch", "--passphrase", "", "--quick-generate-key", uid, "default", "default", "never")
	gen.Env = append(os.Environ(), "GNUPGHOME="+home)
	if out, err := gen.CombinedOutput(); err != nil {
		t.Skipf("cannot generate a test key: %v: %s", err, out)
	}

	w := &world{
		gnupgHome:  home,
		recipient:  uid,
		passDir:    t.TempDir(),
		binpassDir: t.TempDir(),
	}
	// binpass must produce a store pass can read, so both are initialised
	// with GPG; age compatibility is covered by its own tests.
	w.runPass(t, "init", uid)
	w.runBinpass(t, "init", "--gpg", uid)
	return w
}

// result is the observable outcome of one command.
type result struct {
	// stdout is the standard output, verbatim.
	stdout string
	// stderr is the standard error, verbatim.
	stderr string
	// code is the process exit status.
	code int
}

// env returns the environment for a run against dir.
//
// tree(1) picks its glyphs from the locale codeset and its colours from TERM,
// and honours LS_COLORS when set. All three are pinned so that the comparison
// measures binpass rather than the machine it happens to run on.
func (w *world) env(dir string) []string {
	return append(os.Environ(),
		"GNUPGHOME="+w.gnupgHome,
		"PASSWORD_STORE_DIR="+dir,
		"LS_COLORS=",
		"TERM=xterm",
		"LC_ALL=C.UTF-8",
		"BINPASS_CONFIG="+filepath.Join(dir, "..", "nonexistent.yaml"),
	)
}

// run executes a command and captures its outcome.
func run(t *testing.T, bin string, env []string, stdin string, args ...string) result {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = env
	cmd.Stdin = strings.NewReader(stdin)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	code := 0
	var exitErr *exec.ExitError
	if err != nil {
		if !asExitError(err, &exitErr) {
			t.Fatalf("running %s %v: %v", bin, args, err)
		}
		code = exitErr.ExitCode()
	}
	return result{stdout: stdout.String(), stderr: stderr.String(), code: code}
}

// asExitError reports whether err is an *exec.ExitError, storing it in target.
func asExitError(err error, target **exec.ExitError) bool {
	e, ok := err.(*exec.ExitError) //nolint:errorlint // exec never wraps this.
	if ok {
		*target = e
	}
	return ok
}

// runPass runs the reference implementation.
func (w *world) runPass(t *testing.T, args ...string) result {
	t.Helper()
	return run(t, "pass", w.env(w.passDir), "", args...)
}

// runBinpass runs the implementation under test.
func (w *world) runBinpass(t *testing.T, args ...string) result {
	t.Helper()
	return run(t, binpassBin, w.env(w.binpassDir), "", args...)
}

// insertBoth adds the same entry to both stores.
func (w *world) insertBoth(t *testing.T, name, content string) {
	t.Helper()
	if r := run(t, "pass", w.env(w.passDir), content, "insert", "-m", name); r.code != 0 {
		t.Fatalf("pass insert failed: %s", r.stderr)
	}
	if r := run(t, binpassBin, w.env(w.binpassDir), content, "insert", "-m", name); r.code != 0 {
		t.Fatalf("binpass insert failed: %s", r.stderr)
	}
}

// assertSame runs the same command through both and compares stdout and the
// exit code. It is used for the commands the pass ecosystem actually parses.
func (w *world) assertSame(t *testing.T, args ...string) {
	t.Helper()
	want := w.runPass(t, args...)
	got := w.runBinpass(t, args...)

	assert.Equal(t, want.stdout, got.stdout, "stdout of %v", args)
	assert.Equal(t, want.code, got.code, "exit code of %v (pass stderr: %q, binpass stderr: %q)", args, want.stderr, got.stderr)
}

// assertSameEffect runs a mutating command through both and compares the exit
// code and the resulting tree, but not stdout.
//
// pass implements rm, mv and cp by shelling out to `rm -v`, `mv -v` and
// `cp -v`, so its stdout is coreutils' own progress chatter, complete with
// absolute paths and locale-dependent phrasing. Nothing in the ecosystem
// parses it, and reproducing it byte for byte would tie binpass to a
// particular coreutils build, so only the effect is compared.
func (w *world) assertSameEffect(t *testing.T, args ...string) {
	t.Helper()
	want := w.runPass(t, args...)
	got := w.runBinpass(t, args...)

	assert.Equal(t, want.code, got.code, "exit code of %v (pass stderr: %q, binpass stderr: %q)", args, want.stderr, got.stderr)
	assert.Equal(t, w.tree(t, w.passDir), w.tree(t, w.binpassDir), "resulting tree after %v", args)
}

// tree returns the sorted relative paths of every entry file in a store, so
// that two stores can be compared regardless of their root directory.
func (w *world) tree(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".gpg" {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		out = append(out, rel)
		return nil
	})
	require.NoError(t, err)
	sort.Strings(out)
	return out
}

func TestListingMatchesPass(t *testing.T) {
	w := newWorld(t)
	w.insertBoth(t, "github.com/alice", "hunter2\n")
	w.insertBoth(t, "github.com/bob", "s3cret\n")
	w.insertBoth(t, "bank/tinkoff", "money\n")
	w.insertBoth(t, "top", "x\n")

	w.assertSame(t, "ls")
	w.assertSame(t, "ls", "github.com")
	w.assertSame(t, "ls", "bank")
}

func TestBareInvocationListsLikePass(t *testing.T) {
	w := newWorld(t)
	w.insertBoth(t, "a/one", "1\n")
	w.insertBoth(t, "b", "2\n")

	w.assertSame(t)
}

func TestShowMatchesPass(t *testing.T) {
	w := newWorld(t)
	w.insertBoth(t, "github.com/alice", "hunter2\nurl: https://github.com\nusername: alice\n")

	w.assertSame(t, "show", "github.com/alice")
	// Bare `pass name` is a show, and must stay one.
	w.assertSame(t, "github.com/alice")
}

func TestShowPreservesExactBytes(t *testing.T) {
	w := newWorld(t)
	// No trailing newline: pass round-trips through base64 precisely so this
	// case survives, and binpass must match.
	w.insertBoth(t, "raw", "no-trailing-newline")

	w.assertSame(t, "show", "raw")
}

func TestMissingEntryMatchesPass(t *testing.T) {
	w := newWorld(t)
	w.insertBoth(t, "present", "x\n")

	want := w.runPass(t, "show", "absent")
	got := w.runBinpass(t, "show", "absent")

	assert.Equal(t, want.code, got.code, "a missing entry must fail the same way")
	assert.Equal(t, 1, got.code)
	assert.Equal(t, strings.TrimSpace(want.stderr), strings.TrimSpace(got.stderr))
}

func TestEmptyStoreMatchesPass(t *testing.T) {
	w := newWorld(t)

	want := w.runPass(t, "show", "")
	got := w.runBinpass(t, "show", "")
	assert.Equal(t, want.code, got.code)
}

func TestFindMatchesPass(t *testing.T) {
	w := newWorld(t)
	w.insertBoth(t, "github.com/alice", "x\n")
	w.insertBoth(t, "gitlab.com/bob", "x\n")
	w.insertBoth(t, "bank/tinkoff", "x\n")

	w.assertSame(t, "find", "git")
	w.assertSame(t, "find", "alice")
}

func TestRemoveMatchesPass(t *testing.T) {
	w := newWorld(t)
	w.insertBoth(t, "sub/gone", "x\n")
	w.insertBoth(t, "sub/stays", "x\n")

	w.assertSameEffect(t, "rm", "-f", "sub/gone")
	w.assertSame(t, "ls")
}

func TestMoveMatchesPass(t *testing.T) {
	w := newWorld(t)
	w.insertBoth(t, "old/name", "hunter2\n")

	w.assertSameEffect(t, "mv", "-f", "old/name", "new/name")
	w.assertSame(t, "ls")
	w.assertSame(t, "show", "new/name")
}

func TestCopyMatchesPass(t *testing.T) {
	w := newWorld(t)
	w.insertBoth(t, "source", "hunter2\n")

	w.assertSameEffect(t, "cp", "-f", "source", "dest")
	w.assertSame(t, "ls")
	w.assertSame(t, "show", "dest")
}

func TestStoreWrittenByBinpassIsReadableByPass(t *testing.T) {
	w := newWorld(t)
	// Write with binpass, read with pass, against the very same directory.
	r := run(t, binpassBin, w.env(w.passDir), "hunter2\nurl: x\n", "insert", "-m", "written/by-binpass")
	require.Equal(t, 0, r.code, "binpass insert failed: %s", r.stderr)

	got := w.runPass(t, "show", "written/by-binpass")
	assert.Equal(t, 0, got.code, "pass could not read what binpass wrote: %s", got.stderr)
	assert.Equal(t, "hunter2\nurl: x\n", got.stdout)
}

func TestStoreWrittenByPassIsReadableByBinpass(t *testing.T) {
	w := newWorld(t)
	r := run(t, "pass", w.env(w.binpassDir), "hunter2\nurl: x\n", "insert", "-m", "written/by-pass")
	require.Equal(t, 0, r.code, "pass insert failed: %s", r.stderr)

	got := w.runBinpass(t, "show", "written/by-pass")
	assert.Equal(t, 0, got.code, "binpass could not read what pass wrote: %s", got.stderr)
	assert.Equal(t, "hunter2\nurl: x\n", got.stdout)
}

func TestGeneratedEntryIsReadableByPass(t *testing.T) {
	w := newWorld(t)
	r := run(t, binpassBin, w.env(w.passDir), "", "generate", "-f", "generated", "32")
	require.Equal(t, 0, r.code, "%s", r.stderr)

	got := w.runPass(t, "show", "generated")
	require.Equal(t, 0, got.code, "%s", got.stderr)
	assert.Len(t, strings.TrimRight(got.stdout, "\n"), 32)
}

func TestTreeLayoutIsByteIdentical(t *testing.T) {
	w := newWorld(t)
	// A deep, mixed tree exercises every connector and continuation glyph.
	for _, name := range []string{
		"a/b/c/deep", "a/b/other", "a/sibling", "z/last", "root",
	} {
		w.insertBoth(t, name, "x\n")
	}

	want := w.runPass(t, "ls")
	got := w.runBinpass(t, "ls")
	assert.Equal(t, []byte(want.stdout), []byte(got.stdout), "the rendered tree must match byte for byte")
}
