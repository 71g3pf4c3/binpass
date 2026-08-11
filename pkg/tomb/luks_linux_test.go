//go:build linux

package tomb

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/71g3pf4c3/binpass/pkg/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

// newTestLUKS returns a LUKS backend wired to a fake runner and a throwaway
// age identity, plus the recipient to encrypt to.
func newTestLUKS(t *testing.T) (*LUKS, *fakeRunner, string) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	f := &fakeRunner{fail: map[string]error{}, output: map[string][]byte{}}
	l := &LUKS{runner: f.run}
	l.SetIdentities(func() ([]age.Identity, error) { return []age.Identity{id}, nil })
	return l, f, id.Recipient().String()
}

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

func TestLUKSInitBuildsTheRightCommands(t *testing.T) {
	l, f, rcp := newTestLUKS(t)
	dir := storeWithState(t)

	require.NoError(t, l.Init(dir, []string{rcp}, 64<<20))

	// Format, unlock, make a filesystem, lock again. An empty store needs
	// no seeding, so no mount happens.
	assert.Equal(t, []string{"cryptsetup", "cryptsetup", "mkfs.ext4", "cryptsetup"}, f.names())

	format := f.find("cryptsetup", "luksFormat")
	require.NotNil(t, format)
	assert.Contains(t, format.args, "--batch-mode", "a prompt would hang a non-interactive run")
	assert.Contains(t, format.args, "luks2")
	assert.Contains(t, format.args, filepath.Join(dir, luksImageName))

	// The key reaches cryptsetup on stdin, which is the whole point of
	// --key-file=-.
	assert.Contains(t, format.args, "--key-file")
	assert.Contains(t, format.args, "-")
	assert.Len(t, format.stdin, luksKeySize)
}

func TestLUKSInitNeverPutsTheKeyOnDiskOrInArgv(t *testing.T) {
	l, f, rcp := newTestLUKS(t)
	dir := storeWithState(t)

	require.NoError(t, l.Init(dir, []string{rcp}, 64<<20))

	format := f.find("cryptsetup", "luksFormat")
	require.NotNil(t, format)
	key := format.stdin
	require.Len(t, key, luksKeySize)

	// Nothing in the arguments may contain the key: /proc publishes those
	// to every process on the machine.
	for _, c := range f.calls {
		for _, a := range c.args {
			assert.NotContains(t, a, string(key), "the key must not appear in argv")
		}
	}

	// Nothing on disk may contain it either, except the age-encrypted file.
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, rerr := os.ReadFile(path) //nolint:gosec // walking a temp dir the test made.
		if rerr != nil {
			return rerr
		}
		assert.NotContains(t, string(data), string(key), "the plaintext key must not be written to %s", path)
		return nil
	})
	require.NoError(t, err)

	// The encrypted key must be readable back, or the container is lost.
	got, err := l.readEncryptedKey(filepath.Join(dir, luksKeyName))
	require.NoError(t, err)
	assert.Equal(t, key, got)
}

func TestLUKSInitRefusesToOverwriteAnExistingContainer(t *testing.T) {
	l, _, rcp := newTestLUKS(t)
	dir := storeWithState(t)

	require.NoError(t, l.Init(dir, []string{rcp}, 64<<20))
	err := l.Init(dir, []string{rcp}, 64<<20)
	assert.ErrorContains(t, err, "already exists",
		"a second init would throw away the key to the first container")
}

func TestLUKSInitRejectsATinyContainer(t *testing.T) {
	l, _, rcp := newTestLUKS(t)
	dir := storeWithState(t)

	err := l.Init(dir, []string{rcp}, 1024)
	assert.ErrorContains(t, err, "too small")
}

func TestLUKSInitCleansUpAfterAFailedFormat(t *testing.T) {
	l, f, rcp := newTestLUKS(t)
	dir := storeWithState(t)
	f.fail["cryptsetup"] = errors.New("exit status 1")

	err := l.Init(dir, []string{rcp}, 64<<20)
	require.Error(t, err)

	// A half-made container and an orphaned key are worse than nothing:
	// the next init would refuse, and the key opens something that does
	// not exist.
	assert.NoFileExists(t, filepath.Join(dir, luksImageName))
	assert.NoFileExists(t, filepath.Join(dir, luksKeyName))
}

func TestLUKSInitMovesExistingEntriesIntoTheContainer(t *testing.T) {
	l, f, rcp := newTestLUKS(t)
	dir := storeWithState(t)

	require.NoError(t, os.MkdirAll(filepath.Join(dir, "github.com"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "github.com", "alice.age"), []byte("ciphertext"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".age-recipients"), []byte(rcp+"\n"), 0o600))

	require.NoError(t, l.Init(dir, []string{rcp}, 64<<20))

	// The entry is gone from the plaintext store: leaving a copy beside the
	// container would defeat the whole exercise.
	assert.NoFileExists(t, filepath.Join(dir, "github.com", "alice.age"))
	// Dotfiles stay: the recipients file is needed to encrypt anything.
	assert.FileExists(t, filepath.Join(dir, ".age-recipients"))
	assert.FileExists(t, filepath.Join(dir, luksImageName))

	assert.Contains(t, f.names(), "mount")
	assert.Contains(t, f.names(), "umount")
}

func TestLUKSOpenUnlocksAndMounts(t *testing.T) {
	l, f, rcp := newTestLUKS(t)
	dir := storeWithState(t)
	require.NoError(t, l.Init(dir, []string{rcp}, 64<<20))
	f.calls = nil

	require.NoError(t, l.Open(dir, 30*time.Minute))

	open := f.find("cryptsetup", "open")
	require.NotNil(t, open)
	assert.Contains(t, open.args, filepath.Join(dir, luksImageName))
	assert.Len(t, open.stdin, luksKeySize, "the key must reach cryptsetup on stdin")

	mount := f.find("mount", "")
	require.NotNil(t, mount)
	assert.Equal(t, []string{"/dev/mapper/" + mapperName(dir), dir}, mount.args)

	// The state must record enough to close a tomb whose process died.
	st, err := LoadState(dir)
	require.NoError(t, err)
	assert.Equal(t, BackendLUKS, st.Backend)
	assert.Equal(t, mapperName(dir), st.MapperName)
	assert.Equal(t, 30*time.Minute, st.Timer)
	assert.Equal(t, os.Getpid(), st.PID, "a timed open leaves a process to close it")
}

func TestLUKSOpenWithoutATimerRecordsNoPID(t *testing.T) {
	l, _, rcp := newTestLUKS(t)
	dir := storeWithState(t)
	require.NoError(t, l.Init(dir, []string{rcp}, 64<<20))

	require.NoError(t, l.Open(dir, 0))

	// Without a timer the command returns immediately, so recording its PID
	// would make `status` call every cleanly opened tomb a crash.
	st, err := LoadState(dir)
	require.NoError(t, err)
	assert.Zero(t, st.PID)
	assert.False(t, st.IsStale())
}

func TestLUKSOpenWithoutAContainer(t *testing.T) {
	l, _, _ := newTestLUKS(t)
	dir := storeWithState(t)

	assert.ErrorIs(t, l.Open(dir, 0), ErrNotInitialised)
}

func TestLUKSOpenLocksTheContainerAgainWhenMountFails(t *testing.T) {
	l, f, rcp := newTestLUKS(t)
	dir := storeWithState(t)
	require.NoError(t, l.Init(dir, []string{rcp}, 64<<20))
	f.calls = nil
	f.fail["mount"] = errors.New("exit status 32")

	require.Error(t, l.Open(dir, 0))

	// An unlocked container left behind after a failed mount is plaintext
	// exposed with nothing recording that it happened.
	assert.NotNil(t, f.find("cryptsetup", "close"), "the container must be locked again")
	_, err := LoadState(dir)
	assert.True(t, os.IsNotExist(err), "no state may be recorded for a tomb that did not open")
}

func TestLUKSOpenWithoutIdentities(t *testing.T) {
	l, _, rcp := newTestLUKS(t)
	dir := storeWithState(t)
	require.NoError(t, l.Init(dir, []string{rcp}, 64<<20))

	l.SetIdentities(nil)
	err := l.Open(dir, 0)
	assert.ErrorIs(t, err, crypto.ErrNoIdentity)
}

func TestLUKSCloseWhenNothingIsMapped(t *testing.T) {
	l, _, _ := newTestLUKS(t)
	dir := storeWithState(t)

	// No mapping exists, so there is nothing to close, and saying otherwise
	// would tell the user their store is protected when it is not.
	assert.ErrorIs(t, l.Close(dir, false), ErrNotOpen)
}

func TestLUKSErrorsExplainThemselves(t *testing.T) {
	for name, tc := range map[string]struct {
		output string
		want   string
		is     error
	}{
		"needs root": {
			output: "cryptsetup: Failed to open /dev/mapper/control: Permission denied",
			want:   "root",
			is:     ErrNeedRoot,
		},
		"no dm-crypt": {
			output: "device-mapper: reload ioctl failed: No such file or directory",
			want:   "modprobe dm_crypt",
		},
		"wrong key": {
			output: "No key available with this passphrase.",
			want:   "does not unlock",
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := classifyLUKSError("cryptsetup", []byte(tc.output), errors.New("exit status 1"))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
			if tc.is != nil {
				assert.ErrorIs(t, err, tc.is)
			}
			// The reason from cryptsetup must survive: without it the user
			// is told something is wrong but not what.
			assert.Contains(t, err.Error(), strings.Split(tc.output, "\n")[0])
		})
	}
}

func TestLUKSErrorWithNoOutput(t *testing.T) {
	err := classifyLUKSError("mount", nil, errors.New("exit status 32"))
	assert.ErrorContains(t, err, "mount")
	assert.ErrorContains(t, err, "exit status 32")
}

func TestMapperNamesDifferPerStore(t *testing.T) {
	a := mapperName("/home/you/.password-store")
	b := mapperName("/home/you/work-store")

	assert.NotEqual(t, a, b, "two stores open at once must not collide in /dev/mapper")
	assert.Equal(t, a, mapperName("/home/you/.password-store"),
		"the name must be stable, or a crashed tomb cannot be found again")
	assert.True(t, strings.HasPrefix(a, "binpass-"))
}

func TestDetectBackendReadsTheContainerOnDisk(t *testing.T) {
	dir := t.TempDir()
	_, ok := DetectBackend(dir)
	assert.False(t, ok, "an empty store has no tomb")

	require.NoError(t, os.WriteFile(filepath.Join(dir, luksImageName), []byte("x"), 0o600))
	b, ok := DetectBackend(dir)
	require.True(t, ok)
	assert.Equal(t, BackendLUKS, b)
	assert.True(t, HasContainer(dir))
}

func TestLUKSStatusWithoutAContainer(t *testing.T) {
	l, _, _ := newTestLUKS(t)
	dir := storeWithState(t)

	st, open, err := l.Status(dir)
	require.NoError(t, err)
	assert.False(t, open)
	assert.Empty(t, st.Backend)
}

func TestLUKSStatusReportsClosedWhenTheMappingIsGone(t *testing.T) {
	l, _, rcp := newTestLUKS(t)
	dir := storeWithState(t)
	require.NoError(t, l.Init(dir, []string{rcp}, 64<<20))
	require.NoError(t, l.Open(dir, 0))

	// The state file says open, but no mapping exists: after a crash the
	// kernel is the authority, not our own bookkeeping.
	st, open, err := l.Status(dir)
	require.NoError(t, err)
	assert.False(t, open)
	assert.Equal(t, BackendLUKS, st.Backend)
}

func TestCopyTreeSkipsTheContainerItself(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()

	require.NoError(t, os.MkdirAll(filepath.Join(src, "sub"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(src, "sub", "entry.age"), []byte("data"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(src, luksImageName), []byte("container"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(src, luksKeyName), []byte("key"), 0o600))

	require.NoError(t, copyTree(src, dst, luksImageName, luksKeyName))

	assert.FileExists(t, filepath.Join(dst, "sub", "entry.age"))
	// Copying the container into itself would double the store's size and
	// nest a tomb inside a tomb.
	assert.NoFileExists(t, filepath.Join(dst, luksImageName))
	assert.NoFileExists(t, filepath.Join(dst, luksKeyName))
}

func TestCopiedEntriesArePrivate(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(src, "entry.age"), []byte("data"), 0o644))

	require.NoError(t, copyTree(src, dst))

	info, err := os.Stat(filepath.Join(dst, "entry.age"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(),
		"a world-readable entry inside the container defeats the point")
}

func TestCreateSparseFileReportsItsSizeWithoutOccupyingIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "image")
	const size = 64 << 20

	require.NoError(t, createSparseFile(path, size))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, int64(size), info.Size())
	// 512-byte blocks: a sparse file occupies far fewer than its length.
	st, ok := info.Sys().(*syscall.Stat_t)
	require.True(t, ok)
	assert.Less(t, st.Blocks*512, int64(size),
		"the container must not cost its full size up front")
}

func TestZeroClearsTheKey(t *testing.T) {
	b := []byte{1, 2, 3, 4}
	zero(b)
	assert.Equal(t, []byte{0, 0, 0, 0}, b)
}

// TestLUKSAgainstRealCryptsetup runs the whole cycle against the real tools.
// It needs root and a kernel with dm-crypt, so it skips everywhere else; the
// privileged container in Dockerfile.luks is where it actually runs.
func TestLUKSAgainstRealCryptsetup(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: cryptsetup requires /dev/mapper/control")
	}
	for _, bin := range []string{"cryptsetup", "mkfs.ext4", "mount", "umount"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not found on PATH", bin)
		}
	}
	// Root is not enough: an unprivileged container has /dev/mapper/control
	// missing or unusable, and a kernel without dm_mod cannot be blamed on
	// this code.
	if _, err := os.Stat("/dev/mapper/control"); err != nil {
		t.Skip("no /dev/mapper/control: run this image with --privileged")
	}

	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	dir := storeWithState(t)
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".age-recipients"),
		[]byte(id.Recipient().String()+"\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "entry.age"), []byte("ciphertext"), 0o600))

	l, err := newLUKS()
	require.NoError(t, err)
	l.SetIdentities(func() ([]age.Identity, error) { return []age.Identity{id}, nil })

	require.NoError(t, l.Init(dir, []string{id.Recipient().String()}, 64<<20))
	t.Cleanup(func() { _ = l.Close(dir, false) })

	// After init the entry lives inside the container, not beside it.
	assert.NoFileExists(t, filepath.Join(dir, "entry.age"))

	require.NoError(t, l.Open(dir, 0))
	data, err := os.ReadFile(filepath.Join(dir, "entry.age"))
	require.NoError(t, err)
	assert.Equal(t, "ciphertext", string(data), "the entry must come back through the mount")

	_, open, err := l.Status(dir)
	require.NoError(t, err)
	assert.True(t, open)

	require.NoError(t, l.Close(dir, false))
	_, open, err = l.Status(dir)
	require.NoError(t, err)
	assert.False(t, open)
	// Closed: the entry is inside the container and invisible from outside.
	assert.NoFileExists(t, filepath.Join(dir, "entry.age"))
	assert.FileExists(t, filepath.Join(dir, luksImageName))
}

// TestIsWithinAcceptsDotfiles guards a fix that mattered: the check rejected
// any path whose first byte was a dot, so ".age-recipients" — the file that
// says who the store is encrypted to — looked like an attempt to escape the
// root.
func TestIsWithinAcceptsDotfiles(t *testing.T) {
	root := "/store"
	for _, p := range []string{
		"/store",
		"/store/.age-recipients",
		"/store/.gpg-id",
		"/store/sub/entry.age",
	} {
		assert.True(t, isWithin(root, p), "%q is inside the store", p)
	}
	for _, p := range []string{
		"/store/../escape",
		"/etc/passwd",
		"/storeage/entry",
	} {
		assert.False(t, isWithin(root, p), "%q is outside the store", p)
	}
}

func TestLUKSNameAndConstruction(t *testing.T) {
	l := &LUKS{}
	assert.Equal(t, BackendLUKS, l.Name())

	// newLUKS refuses up front when cryptsetup is missing, which is a far
	// better message than the failure that would otherwise surface from the
	// middle of Init.
	if _, err := exec.LookPath("cryptsetup"); err != nil {
		_, nerr := newLUKS()
		assert.ErrorContains(t, nerr, "cryptsetup not found")
		return
	}
	got, err := newLUKS()
	require.NoError(t, err)
	assert.NotNil(t, got)
}

func TestExecRunnerReportsOutputAndStatus(t *testing.T) {
	out, err := execRunner("sh", nil, "-c", "echo hello")
	require.NoError(t, err)
	assert.Contains(t, string(out), "hello")

	// stdin is how the container key reaches cryptsetup, so it has to work.
	out, err = execRunner("cat", []byte("piped"), "-")
	require.NoError(t, err)
	assert.Equal(t, "piped", string(out))

	_, err = execRunner("sh", nil, "-c", "exit 3")
	assert.Error(t, err)
}
