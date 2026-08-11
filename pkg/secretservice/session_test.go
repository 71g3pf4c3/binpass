package secretservice_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/71g3pf4c3/binpass/pkg/secretservice"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Second Oakley Group, RFC 2409 §6.2 — repeated here rather than exported,
// so that the test derives the key the way a client library does instead of
// borrowing the implementation's own constants. A test that shares the code
// under test cannot detect a wrong constant.
var (
	testPrime, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"+
		"FFFFFFFFFFFFFFFF", 16)
	testGen = big.NewInt(2)
)

// clientSide performs the client half of the exchange the way libsecret
// does, returning its public key and the key it derives.
type clientSide struct {
	priv *big.Int
	pub  []byte
}

func newClientSide(t *testing.T) *clientSide {
	t.Helper()
	priv, err := rand.Int(rand.Reader, testPrime)
	require.NoError(t, err)
	pub := new(big.Int).Exp(testGen, priv, testPrime)
	return &clientSide{priv: priv, pub: fillToPrime(pub)}
}

// deriveKey computes the AES key from the server's public key, following the
// algorithm name: HKDF-SHA256 with an all-zero salt over the shared secret.
func (c *clientSide) deriveKey(serverPub []byte) []byte {
	shared := new(big.Int).Exp(new(big.Int).SetBytes(serverPub), c.priv, testPrime)

	extract := hmac.New(sha256.New, make([]byte, sha256.Size))
	extract.Write(fillToPrime(shared))
	prk := extract.Sum(nil)

	expand := hmac.New(sha256.New, prk)
	expand.Write([]byte{0x01})
	return expand.Sum(nil)[:16]
}

func fillToPrime(n *big.Int) []byte {
	out := make([]byte, (testPrime.BitLen()+7)/8)
	n.FillBytes(out)
	return out
}

func TestPlainSessionPassesSecretsThrough(t *testing.T) {
	s := secretservice.NewPlainSession("s1")
	assert.Equal(t, secretservice.AlgPlain, s.Algorithm)

	value, param, err := s.Encrypt([]byte("hunter2"))
	require.NoError(t, err)
	assert.Equal(t, "hunter2", string(value))
	assert.Empty(t, param, "plain carries no IV")

	back, err := s.Decrypt(value, param)
	require.NoError(t, err)
	assert.Equal(t, "hunter2", string(back))
}

// TestDHInteroperatesWithAnIndependentImplementation is the test that
// matters: the key is derived twice, once by the provider and once by code
// written from the specification, and a secret encrypted by one must decrypt
// with the other. libsecret asks for this algorithm by default, so getting
// it subtly wrong means the provider does not work with most clients.
func TestDHInteroperatesWithAnIndependentImplementation(t *testing.T) {
	client := newClientSide(t)

	session, serverPub, err := secretservice.NewDHSession("s1", client.pub)
	require.NoError(t, err)
	assert.Equal(t, secretservice.AlgDH, session.Algorithm)
	assert.Len(t, serverPub, 128, "the public key must be the full modulus width")

	clientKey := client.deriveKey(serverPub)

	// Provider encrypts, client decrypts.
	value, iv, err := session.Encrypt([]byte("correct-horse-battery-staple"))
	require.NoError(t, err)
	assert.Len(t, iv, aes.BlockSize)
	assert.NotContains(t, string(value), "correct-horse",
		"the secret must not travel in the clear")

	got := clientDecrypt(t, clientKey, iv, value)
	assert.Equal(t, "correct-horse-battery-staple", string(got))

	// Client encrypts, provider decrypts: the direction used by SetSecret.
	sent := clientEncrypt(t, clientKey, []byte("from the client"))
	back, err := session.Decrypt(sent.value, sent.iv)
	require.NoError(t, err)
	assert.Equal(t, "from the client", string(back))
}

// TestDHKeyDerivationIsStableAcrossLengths guards a bug that would appear
// roughly one exchange in 256: a shared secret whose leading byte is zero,
// hashed without padding to the modulus width, derives a different key on
// each side.
func TestDHKeyDerivationIsStableAcrossLengths(t *testing.T) {
	for i := 0; i < 64; i++ {
		client := newClientSide(t)
		session, serverPub, err := secretservice.NewDHSession("s", client.pub)
		require.NoError(t, err)

		clientKey := client.deriveKey(serverPub)
		value, iv, err := session.Encrypt([]byte("x"))
		require.NoError(t, err)

		got := clientDecrypt(t, clientKey, iv, value)
		require.Equal(t, "x", string(got), "iteration %d: both sides must derive the same key", i)
	}
}

func TestDHRejectsDegeneratePublicKeys(t *testing.T) {
	// 0, 1 and p-1 all force the shared secret to a value the client
	// chooses, which would let a client dictate the key instead of
	// negotiating it.
	for name, pub := range map[string][]byte{
		"zero":        fillToPrime(big.NewInt(0)),
		"one":         fillToPrime(big.NewInt(1)),
		"p minus one": fillToPrime(new(big.Int).Sub(testPrime, big.NewInt(1))),
		"empty":       {},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := secretservice.NewDHSession("s", pub)
			assert.Error(t, err, "%s must be refused", name)
		})
	}
}

func TestDHRoundTripsEveryLengthAroundTheBlockSize(t *testing.T) {
	client := newClientSide(t)
	session, serverPub, err := secretservice.NewDHSession("s", client.pub)
	require.NoError(t, err)
	clientKey := client.deriveKey(serverPub)

	// Lengths either side of a block boundary, including empty and exactly
	// one block: PKCS#7 must add a full block of padding when the input is
	// already aligned, or unpadding an aligned secret eats real bytes.
	for _, n := range []int{0, 1, 15, 16, 17, 31, 32, 33} {
		plaintext := bytes.Repeat([]byte("a"), n)
		value, iv, err := session.Encrypt(plaintext)
		require.NoError(t, err)

		got := clientDecrypt(t, clientKey, iv, value)
		assert.Equal(t, plaintext, got, "length %d must round-trip", n)

		back, err := session.Decrypt(value, iv)
		require.NoError(t, err)
		assert.Equal(t, plaintext, back, "length %d must round-trip through the provider", n)
	}
}

func TestDecryptRejectsMalformedInput(t *testing.T) {
	client := newClientSide(t)
	session, _, err := secretservice.NewDHSession("s", client.pub)
	require.NoError(t, err)

	for name, tc := range map[string]struct{ value, iv []byte }{
		"short IV":             {bytes.Repeat([]byte("x"), 16), []byte("short")},
		"no IV":                {bytes.Repeat([]byte("x"), 16), nil},
		"unaligned ciphertext": {bytes.Repeat([]byte("x"), 17), bytes.Repeat([]byte("i"), 16)},
		"empty ciphertext":     {nil, bytes.Repeat([]byte("i"), 16)},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := session.Decrypt(tc.value, tc.iv)
			assert.Error(t, err)
		})
	}

	// Valid shape, wrong key: the padding check is what catches it, and it
	// must be an error rather than silently returning garbage as a password.
	badKey := bytes.Repeat([]byte("k"), 16)
	sent := clientEncrypt(t, badKey, []byte("secret"))
	_, err = session.Decrypt(sent.value, sent.iv)
	assert.Error(t, err, "a ciphertext from another key must not decrypt")
}

type encrypted struct {
	value []byte
	iv    []byte
}

// clientEncrypt encrypts as a client library would: AES-128-CBC, PKCS#7.
func clientEncrypt(t *testing.T, key, plaintext []byte) encrypted {
	t.Helper()
	block, err := aes.NewCipher(key)
	require.NoError(t, err)

	iv := make([]byte, block.BlockSize())
	_, err = rand.Read(iv)
	require.NoError(t, err)

	n := block.BlockSize() - len(plaintext)%block.BlockSize()
	padded := append(append([]byte(nil), plaintext...), bytes.Repeat([]byte{byte(n)}, n)...)

	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
	return encrypted{value: out, iv: iv}
}

// clientDecrypt decrypts and unpads as a client library would.
func clientDecrypt(t *testing.T, key, iv, value []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	require.Equal(t, 0, len(value)%block.BlockSize())

	out := make([]byte, len(value))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, value)

	n := int(out[len(out)-1])
	require.Greater(t, n, 0)
	require.LessOrEqual(t, n, block.BlockSize())
	return out[:len(out)-n]
}
