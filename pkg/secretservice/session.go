package secretservice

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
)

// The transport algorithms named by the specification.
const (
	// AlgPlain sends secrets unencrypted over the bus. The bus socket is
	// already restricted to this user, so this is what most clients use.
	AlgPlain = "plain"
	// AlgDH negotiates a shared key by Diffie-Hellman and encrypts the
	// secret with it. libsecret asks for this by default, so a provider
	// without it does not work with the client library most programs use.
	AlgDH = "dh-ietf1024-sha256-aes128-cbc-pkcs7"
)

// ErrUnsupportedAlgorithm reports a transport algorithm this provider does
// not implement.
var ErrUnsupportedAlgorithm = errors.New("secretservice: unsupported algorithm")

// Second Oakley Group, RFC 2409 §6.2: the 1024-bit MODP group the
// specification names. It is not a strong group by present standards, but it
// is the one written into the protocol, and a client that asks for
// dh-ietf1024 will not accept anything else.
//
// That matters less than it appears: this key protects a secret travelling
// between two processes of the same user over a socket only that user can
// open. It is defence against a bus proxy that logs traffic, not against an
// adversary who can factor a 1024-bit modulus.
var (
	dhPrime = mustPrime("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381" +
		"FFFFFFFFFFFFFFFF")
	dhGenerator = big.NewInt(2)
)

// dhKeyLen is the AES key length the algorithm names: AES-128.
const dhKeyLen = 16

// Session is one client's transport context.
//
// A client opens a session, uses it for as long as it likes, and closes it.
// The negotiated key lives here and nowhere else, so closing a session is
// what makes the key unrecoverable.
type Session struct {
	// ID identifies the session; it is the last element of its object path.
	ID string
	// Algorithm is the negotiated transport algorithm.
	Algorithm string
	// key is the AES key derived from the exchange. Empty for plain.
	key []byte
}

// NewPlainSession returns a session that sends secrets unencrypted.
func NewPlainSession(id string) *Session {
	return &Session{ID: id, Algorithm: AlgPlain}
}

// NewDHSession completes a Diffie-Hellman exchange with a client's public
// key, returning the session and the public key to send back.
func NewDHSession(id string, clientPublic []byte) (*Session, []byte, error) {
	if len(clientPublic) == 0 {
		return nil, nil, errors.New("secretservice: empty client public key")
	}

	// A private exponent the size of the modulus. Anything shorter narrows
	// the search a passive observer would have to do.
	priv, err := rand.Int(rand.Reader, dhPrime)
	if err != nil {
		return nil, nil, fmt.Errorf("secretservice: generating a private key: %w", err)
	}

	clientPub := new(big.Int).SetBytes(clientPublic)
	// Reject the degenerate public keys: 0, 1, and p-1 force the shared
	// secret to a value the client picks, which would let a client choose
	// the key rather than negotiate it.
	if !validDHPublic(clientPub) {
		return nil, nil, errors.New("secretservice: refusing a degenerate client public key")
	}

	shared := new(big.Int).Exp(clientPub, priv, dhPrime)
	serverPub := new(big.Int).Exp(dhGenerator, priv, dhPrime)

	return &Session{
		ID:        id,
		Algorithm: AlgDH,
		key:       hkdfSHA256(padToPrime(shared), dhKeyLen),
	}, padToPrime(serverPub), nil
}

// validDHPublic reports whether a client's public key is usable.
func validDHPublic(pub *big.Int) bool {
	if pub.Sign() <= 0 {
		return false
	}
	one := big.NewInt(1)
	if pub.Cmp(one) <= 0 {
		return false
	}
	pMinus1 := new(big.Int).Sub(dhPrime, one)
	return pub.Cmp(pMinus1) < 0
}

// Encrypt prepares a secret for transport, returning the value and the
// parameter the specification carries the IV in.
func (s *Session) Encrypt(plaintext []byte) (value, parameter []byte, err error) {
	if s.Algorithm == AlgPlain {
		return plaintext, nil, nil
	}

	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, nil, err
	}
	iv := make([]byte, block.BlockSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, fmt.Errorf("secretservice: generating an IV: %w", err)
	}

	padded := padPKCS7(plaintext, block.BlockSize())
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
	return out, iv, nil
}

// Decrypt recovers a secret a client sent.
func (s *Session) Decrypt(value, parameter []byte) ([]byte, error) {
	if s.Algorithm == AlgPlain {
		return value, nil
	}

	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}
	if len(parameter) != block.BlockSize() {
		return nil, fmt.Errorf("secretservice: IV is %d bytes, want %d", len(parameter), block.BlockSize())
	}
	if len(value) == 0 || len(value)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("secretservice: ciphertext is %d bytes, not a multiple of the block size", len(value))
	}

	out := make([]byte, len(value))
	cipher.NewCBCDecrypter(block, parameter).CryptBlocks(out, value)
	return unpadPKCS7(out, block.BlockSize())
}

// hkdfSHA256 derives a key from the shared secret, following the HKDF the
// algorithm name calls for: extract with an all-zero salt, then one round of
// expansion, which is all that is needed for a key this short.
func hkdfSHA256(shared []byte, length int) []byte {
	extract := hmac.New(sha256.New, make([]byte, sha256.Size))
	extract.Write(shared)
	prk := extract.Sum(nil)

	expand := hmac.New(sha256.New, prk)
	expand.Write([]byte{0x01})
	return expand.Sum(nil)[:length]
}

// padToPrime left-pads a value to the modulus width.
//
// Both sides must agree on the byte length before hashing: a shared secret
// that happens to start with a zero byte would otherwise be hashed one byte
// short, and the two ends would derive different keys perhaps one time in
// 256. That failure is rare enough to survive testing and constant enough to
// be reported as "sometimes it does not work".
func padToPrime(n *big.Int) []byte {
	size := (dhPrime.BitLen() + 7) / 8
	out := make([]byte, size)
	n.FillBytes(out)
	return out
}

// padPKCS7 appends padding to a block boundary. A full block of padding is
// added when the input is already aligned, so that unpadding is never
// ambiguous.
func padPKCS7(b []byte, blockSize int) []byte {
	n := blockSize - len(b)%blockSize
	out := make([]byte, len(b)+n)
	copy(out, b)
	for i := len(b); i < len(out); i++ {
		out[i] = byte(n)
	}
	return out
}

// unpadPKCS7 removes padding, rejecting anything malformed.
func unpadPKCS7(b []byte, blockSize int) ([]byte, error) {
	if len(b) == 0 || len(b)%blockSize != 0 {
		return nil, errors.New("secretservice: bad padding length")
	}
	n := int(b[len(b)-1])
	if n == 0 || n > blockSize || n > len(b) {
		return nil, errors.New("secretservice: bad padding")
	}
	// Every padding byte must carry the same value, or the padding is not
	// PKCS#7 and the plaintext is not what the sender wrote.
	for _, c := range b[len(b)-n:] {
		if int(c) != n {
			return nil, errors.New("secretservice: bad padding")
		}
	}
	return b[:len(b)-n], nil
}

// mustPrime parses a hex modulus at init time. A malformed constant here is
// a programming error, not a runtime condition.
func mustPrime(hex string) *big.Int {
	n, ok := new(big.Int).SetString(hex, 16)
	if !ok {
		panic("secretservice: malformed DH prime constant")
	}
	return n
}
