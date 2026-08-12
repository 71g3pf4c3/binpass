package tomb

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These run on every platform, deliberately. The backend itself is macOS
// only, but the arguments are the part worth checking and a test that only
// runs on a Mac is one that runs when someone happens to have a Mac.

func TestCreateArgsAskForAnEncryptedAPFSBundle(t *testing.T) {
	args := createArgs("/store/store.sparsebundle", 1024)
	joined := strings.Join(args, " ")

	assert.Equal(t, "create", args[0])
	assert.Contains(t, joined, "-type SPARSEBUNDLE")
	assert.Contains(t, joined, "-fs APFS")
	assert.Contains(t, joined, "-encryption AES-256",
		"an unencrypted bundle would defeat the entire feature")
	assert.Contains(t, joined, "-size 1024m", "hdiutil takes megabytes")
	assert.Contains(t, args, "/store/store.sparsebundle")

	// The passphrase goes in on stdin. As an argument it would be visible
	// in ps to every process on the machine.
	assert.Contains(t, args, "-stdinpass")
	for _, a := range args {
		assert.NotContains(t, a, "pass=", "no passphrase may appear in argv")
	}
}

func TestAttachArgsKeepTheMountOutOfFinderAndSpotlight(t *testing.T) {
	args := attachArgs("/store/store.sparsebundle", "/store")
	joined := strings.Join(args, " ")

	assert.Equal(t, "attach", args[0])
	assert.Contains(t, joined, "-mountpoint /store")
	assert.Contains(t, args, "-stdinpass")

	// Not cosmetic: an indexer walking the mount copies entry names into a
	// database outside the tomb, which is the metadata the tomb hides.
	assert.Contains(t, args, "-nobrowse")
	assert.Contains(t, args, "-noidme")
}

func TestDetachArgs(t *testing.T) {
	assert.Equal(t, []string{"detach", "/store"}, detachArgs("/store", false))
	assert.Equal(t, []string{"detach", "/store", "-force"}, detachArgs("/store", true))
}

// TestHdiutilErrorsExplainThemselves covers the three failures a user
// actually hits. hdiutil reports all of them as exit status 1 with the
// detail on stderr, so passing the status through unread leaves the user
// with a number.
func TestHdiutilErrorsExplainThemselves(t *testing.T) {
	for name, tc := range map[string]struct {
		output string
		want   string
		is     error
	}{
		"wrong passphrase": {
			output: "hdiutil: attach failed - Authentication error",
			want:   "does not open this bundle",
		},
		"bundle in use": {
			output: "hdiutil: detach failed - Resource busy",
			want:   "close anything reading the store",
		},
		"no bundle": {
			output: "hdiutil: attach: No such file or directory",
			want:   "not initialised",
			is:     ErrNotInitialised,
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := classifyHdiutilError([]byte(tc.output), errors.New("exit status 1"))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
			if tc.is != nil {
				assert.ErrorIs(t, err, tc.is)
			}
			// The reason from hdiutil has to survive, or the user is told
			// something went wrong but not what.
			assert.Contains(t, err.Error(), strings.Split(tc.output, "\n")[0])
		})
	}
}

func TestHdiutilErrorWithNoOutput(t *testing.T) {
	err := classifyHdiutilError(nil, errors.New("exit status 1"))
	assert.ErrorContains(t, err, "hdiutil")
	assert.ErrorContains(t, err, "exit status 1")
}

func TestBundlePaths(t *testing.T) {
	assert.Equal(t, filepath.Join("/store", "store.sparsebundle"), bundlePath("/store"))
	assert.Equal(t, filepath.Join("/store", "store.sparsebundle.key.age"), bundleKeyPath("/store"))
}

// TestSparseBundleIsDetectedOnEveryPlatform: a store synchronised from a Mac
// must be recognisable on Linux, where it cannot be opened. Reporting "no
// tomb" would tell the user their store is unprotected when it is not.
func TestSparseBundleIsDetectedOnEveryPlatform(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, writeFile(filepath.Join(dir, bundleName), "x"))

	backend, ok := DetectBackend(dir)
	require.True(t, ok)
	assert.Equal(t, BackendSparseBundle, backend)
	assert.True(t, HasContainer(dir))
}

// TestBundleFilesAreNotMistakenForPlaintext guards the check that decides
// whether a tomb is open. Counting the bundle as an entry would make every
// closed store look open, and make init try to seed a bundle with itself.
func TestBundleFilesAreNotMistakenForPlaintext(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, writeFile(filepath.Join(dir, bundleName), "container"))
	require.NoError(t, writeFile(filepath.Join(dir, bundleKeyName), "key"))
	require.NoError(t, writeFile(filepath.Join(dir, ".age-recipients"), "age1..."))

	assert.False(t, hasPlaintext(dir), "a closed bundle store holds no plaintext")

	require.NoError(t, writeFile(filepath.Join(dir, "entry.age"), "secret"))
	assert.True(t, hasPlaintext(dir), "a real entry is plaintext")
}

// TestRandomPassphraseIsPrintableAndUnique: hdiutil reads the passphrase as
// text on stdin, so raw bytes would be mangled by whatever byte happened to
// look like a newline.
func TestRandomPassphraseIsPrintableAndUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 32; i++ {
		p, err := randomPassphrase()
		require.NoError(t, err)
		require.NotEmpty(t, p)

		for _, c := range p {
			assert.True(t, c >= 33 && c <= 126, "passphrase must be printable, got byte %d", c)
		}
		assert.False(t, seen[string(p)], "passphrases must not repeat")
		seen[string(p)] = true
	}
}

// writeFile is a small helper for the tests above.
func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
