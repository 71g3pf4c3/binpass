package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeBinary writes data to a file in a fresh temp directory and returns
// its path, standing in for the photo or key a user would point at.
func writeBinary(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "blob.bin")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

func TestRunBinaryCopyCatSum(t *testing.T) {
	app := newTestApp(t)
	// Bytes that are not valid UTF-8 and not valid base64 padding: the
	// entry must carry them through unchanged.
	data := []byte{0x00, 0xff, 0xfe, 0x81, 'a', 'b', 'c', 0x00, 0x42}
	src := writeBinary(t, data)

	require.NoError(t, app.runBinaryCopy("photo.b64", src, true))
	app.out.Reset()

	require.NoError(t, app.runBinaryCat("photo.b64"))
	assert.Equal(t, data, app.out.Bytes(), "cat must return the original bytes")
	app.out.Reset()

	require.NoError(t, app.runBinarySum("photo.b64"))
	sum := sha256.Sum256(data)
	assert.Equal(t, hex.EncodeToString(sum[:]), strings.TrimSpace(app.out.String()))
}

func TestRunBinaryMoveRemovesOriginal(t *testing.T) {
	app := newTestApp(t)
	data := []byte("a key, in bytes")
	src := writeBinary(t, data)

	require.NoError(t, app.runBinaryMove("key.b64", src, true))

	_, err := os.Stat(src)
	assert.True(t, os.IsNotExist(err), "move must remove the source file")

	s, err := app.Store()
	require.NoError(t, err)
	names, err := s.List("")
	require.NoError(t, err)
	assert.Contains(t, names, "key.b64")
}

func TestRunBinaryCopyDeclinedOverwriteKeepsEntry(t *testing.T) {
	app := newTestApp(t)
	first := writeBinary(t, []byte("first version"))
	second := writeBinary(t, []byte("second version"))

	require.NoError(t, app.runBinaryCopy("photo.b64", first, true))

	// The prompt reads from In; "n" declines, and the command must end
	// quietly with the entry exactly as it was.
	app.In = strings.NewReader("n\n")
	app.out.Reset()
	require.NoError(t, app.runBinaryCopy("photo.b64", second, false))

	app.out.Reset()
	require.NoError(t, app.runBinaryCat("photo.b64"))
	assert.Equal(t, []byte("first version"), app.out.Bytes())
}

func TestRunBinaryCatMissing(t *testing.T) {
	app := newTestApp(t)

	err := app.runBinaryCat("absent.b64")
	require.Error(t, err)
}

func TestRunBinaryCopyMissingSource(t *testing.T) {
	app := newTestApp(t)

	err := app.runBinaryCopy("photo.b64", filepath.Join(t.TempDir(), "no-such-file"), true)
	require.Error(t, err)
}
