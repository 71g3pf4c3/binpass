package binary

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"testing"

	"filippo.io/age"
	"github.com/71g3pf4c3/binpass/pkg/crypto"
	"github.com/71g3pf4c3/binpass/pkg/secret"
	"github.com/71g3pf4c3/binpass/pkg/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newFixture builds an initialised age store in a temporary directory.
func newFixture(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	backend := crypto.NewAge(dir, func() ([]age.Identity, error) {
		return []age.Identity{id}, nil
	})
	s, err := store.New(store.Options{Dir: dir, Backends: []crypto.Crypto{backend}})
	require.NoError(t, err)

	rcp := crypto.Recipient(id.Recipient().String())
	require.NoError(t, s.Init("", []crypto.Recipient{rcp}))
	return s
}

func TestIsBinary(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"photo.b64", true},
		{"dir/photo.b64", true},
		{"note", false},
		{"dir/note", false},
		{".b64", true},
		{"file.b64.txt", false},
	}
	for _, tt := range tests {
		got := IsBinary(tt.name)
		assert.Equal(t, tt.want, got, "IsBinary(%q)", tt.name)
	}
}

func TestCat(t *testing.T) {
	s := newFixture(t)
	payload := []byte("hello, binary world!")
	b64 := base64.StdEncoding.EncodeToString(payload)

	require.NoError(t, s.Set("photo.b64", secret.Parse([]byte(b64))))

	var buf bytes.Buffer
	require.NoError(t, Cat(s, "photo.b64", &buf))
	assert.Equal(t, payload, buf.Bytes())
}

func TestCatNotBinary(t *testing.T) {
	s := newFixture(t)
	err := Cat(s, "plaintext", &bytes.Buffer{})
	assert.ErrorIs(t, err, ErrNotBinary)
}

func TestCatNotFound(t *testing.T) {
	s := newFixture(t)
	err := Cat(s, "missing.b64", &bytes.Buffer{})
	assert.Error(t, err) // store.ErrNotFound
}

func TestSum(t *testing.T) {
	s := newFixture(t)
	payload := []byte("checksum me")
	b64 := base64.StdEncoding.EncodeToString(payload)

	require.NoError(t, s.Set("file.b64", secret.Parse([]byte(b64))))

	got, err := Sum(s, "file.b64")
	require.NoError(t, err)
	want := fmt.Sprintf("%x", sha256.Sum256(payload))
	assert.Equal(t, want, got)
}

func TestSumNotBinary(t *testing.T) {
	s := newFixture(t)
	_, err := Sum(s, "plaintext")
	assert.ErrorIs(t, err, ErrNotBinary)
}

func TestStore(t *testing.T) {
	s := newFixture(t)
	payload := []byte("store this binary")

	require.NoError(t, Store(s, "doc.b64", bytes.NewReader(payload)))

	// Verify round-trip via Cat.
	var buf bytes.Buffer
	require.NoError(t, Cat(s, "doc.b64", &buf))
	assert.Equal(t, payload, buf.Bytes())
}

func TestStoreNotBinary(t *testing.T) {
	s := newFixture(t)
	err := Store(s, "plaintext", bytes.NewReader([]byte("data")))
	assert.ErrorIs(t, err, ErrNotBinary)
}

func TestStoreAndHash(t *testing.T) {
	s := newFixture(t)
	payload := []byte("store and hash this")

	got, err := StoreAndHash(s, "doc.b64", bytes.NewReader(payload))
	require.NoError(t, err)
	want := fmt.Sprintf("%x", sha256.Sum256(payload))
	assert.Equal(t, want, got)

	// Verify the entry was stored.
	var buf bytes.Buffer
	require.NoError(t, Cat(s, "doc.b64", &buf))
	assert.Equal(t, payload, buf.Bytes())
}

func TestStoreAndHashNotBinary(t *testing.T) {
	s := newFixture(t)
	_, err := StoreAndHash(s, "plaintext", bytes.NewReader(nil))
	assert.ErrorIs(t, err, ErrNotBinary)
}

func TestEncodeB64(t *testing.T) {
	input := []byte("hello, binary world!")
	encoded, err := encodeB64(bytes.NewReader(input))
	require.NoError(t, err)

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err)
	assert.Equal(t, input, decoded)
}

func TestEncodeB64Empty(t *testing.T) {
	encoded, err := encodeB64(bytes.NewReader(nil))
	require.NoError(t, err)
	assert.Equal(t, "", encoded)
}

func TestEncodeB64Large(t *testing.T) {
	// 1 MB of data to verify streaming works.
	input := bytes.Repeat([]byte("A"), 1<<20)
	encoded, err := encodeB64(bytes.NewReader(input))
	require.NoError(t, err)

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err)
	assert.Equal(t, input, decoded)
}

func TestDetectBinary(t *testing.T) {
	// Valid single-line base64.
	payload := base64.StdEncoding.EncodeToString([]byte("binary data here"))
	sec := secret.New(payload, "")
	assert.True(t, DetectBinary(sec))

	// Multi-line secret.
	sec2 := secret.New("password", "username: alice\nurl: example.com")
	assert.False(t, DetectBinary(sec2))

	// Short string.
	sec3 := secret.New("abc", "")
	assert.False(t, DetectBinary(sec3))

	// Invalid base64.
	sec4 := secret.New("!!!not-base64!!!", "")
	assert.False(t, DetectBinary(sec4))
}

func TestHashReader(t *testing.T) {
	data := []byte("hash me")
	want := fmt.Sprintf("%x", sha256.Sum256(data))
	got, err := HashReader(bytes.NewReader(data))
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestCatInvalidBase64(t *testing.T) {
	s := newFixture(t)
	// Store invalid base64 in a .b64 entry.
	require.NoError(t, s.Set("bad.b64", secret.Parse([]byte("!!!invalid!!!"))))

	var buf bytes.Buffer
	err := Cat(s, "bad.b64", &buf)
	assert.Error(t, err) // base64 decode error
}

func TestSumInvalidBase64(t *testing.T) {
	s := newFixture(t)
	require.NoError(t, s.Set("bad.b64", secret.Parse([]byte("!!!invalid!!!"))))

	_, err := Sum(s, "bad.b64")
	assert.Error(t, err)
}

func TestRoundTripBinary(t *testing.T) {
	s := newFixture(t)
	// Store a variety of payloads and verify round-trip.
	payloads := [][]byte{
		[]byte("simple text"),
		{0x00, 0x01, 0x02, 0xff},                          // binary with null and high bytes
		bytes.Repeat([]byte{0xde, 0xad, 0xbe, 0xef}, 256), // 1 KB pattern
	}

	for i, payload := range payloads {
		name := fmt.Sprintf("test%d.b64", i)
		require.NoError(t, Store(s, name, bytes.NewReader(payload)), "Store %s", name)

		var buf bytes.Buffer
		require.NoError(t, Cat(s, name, &buf), "Cat %s", name)
		assert.Equal(t, payload, buf.Bytes(), "round-trip %s", name)

		got, err := Sum(s, name)
		require.NoError(t, err, "Sum %s", name)
		want := fmt.Sprintf("%x", sha256.Sum256(payload))
		assert.Equal(t, want, got, "Sum %s", name)
	}
}

func TestStoreOverwrite(t *testing.T) {
	s := newFixture(t)
	require.NoError(t, Store(s, "doc.b64", bytes.NewReader([]byte("v1"))))
	require.NoError(t, Store(s, "doc.b64", bytes.NewReader([]byte("v2"))))

	var buf bytes.Buffer
	require.NoError(t, Cat(s, "doc.b64", &buf))
	assert.Equal(t, []byte("v2"), buf.Bytes())
}

func TestMain(m *testing.M) {
	// Ensure HOME is set for age identity resolution.
	if os.Getenv("HOME") == "" {
		os.Setenv("HOME", "/tmp")
	}
	os.Exit(m.Run())
}
