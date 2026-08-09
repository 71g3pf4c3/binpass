// Package argon2 provides password/secret hashing and verification using
// Argon2id with an encoded, self-describing PHC-style output.
package argon2

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Bounds on the parameters accepted from an encoded hash. They are generous
// enough for any sane configuration and small enough that a corrupt row
// cannot exhaust memory or stall a login.
const (
	// minKeyLen is the shortest derived key that still makes a chance
	// collision infeasible.
	minKeyLen = 16
	// minSaltLen is the shortest salt worth calling a salt.
	minSaltLen = 8
	// minMemoryKiB is the least memory cost accepted, at 8 MiB.
	minMemoryKiB = 8 << 10
	// maxKeyLen bounds the derived key length.
	maxKeyLen = 1024
	// maxSaltLen bounds the salt length.
	maxSaltLen = 1024
	// maxMemoryKiB bounds the memory cost at 4 GiB.
	maxMemoryKiB = 4 << 20
	// maxTime bounds the iteration count.
	maxTime = 64
	// maxWorkKiB bounds memory multiplied by iterations, at four times the
	// cost of the default parameters.
	maxWorkKiB = 4 * (256 << 10) * 3
)

// Params configures Argon2id hashing.
type Params struct {
	// MemoryMiB is the memory cost in mebibytes.
	MemoryMiB uint32
	// Time is the number of iterations.
	Time uint32
	// Threads is the degree of parallelism.
	Threads uint8
	// KeyLen is the derived key length in bytes.
	KeyLen uint32
	// SaltLen is the random salt length in bytes.
	SaltLen uint32
}

// Default returns sensible Argon2id parameters (256 MiB, t=3, p=4).
func Default() Params {
	return Params{MemoryMiB: 256, Time: 3, Threads: 4, KeyLen: 32, SaltLen: 16}
}

// Hasher hashes and verifies secrets with fixed parameters.
type Hasher struct {
	// params are the Argon2id cost parameters.
	params Params
}

// New returns a Hasher with the given parameters.
func New(p Params) *Hasher { return &Hasher{params: p} }

// Hash returns an encoded Argon2id hash of secret.
func (h *Hasher) Hash(secret string) (string, error) {
	salt := make([]byte, h.params.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("argon2: salt: %w", err)
	}
	key := argon2.IDKey([]byte(secret), salt,
		h.params.Time, h.params.MemoryMiB*1024, h.params.Threads, h.params.KeyLen)

	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, h.params.MemoryMiB*1024, h.params.Time, h.params.Threads,
		b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// Verify reports whether secret matches the encoded hash.
func Verify(secret, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, fmt.Errorf("argon2: malformed hash")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, fmt.Errorf("argon2: version: %w", err)
	}
	var memory, time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return false, fmt.Errorf("argon2: params: %w", err)
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("argon2: salt decode: %w", err)
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("argon2: key decode: %w", err)
	}
	// Everything above was read out of the encoded hash, which comes from
	// storage rather than from us. The lower bounds matter as much as the
	// upper ones: argon2.IDKey panics on a zero time or threads count, and a
	// hash naming a one-byte key matches any secret with probability 1/256,
	// which is an authentication bypass rather than a crash.
	if memory < minMemoryKiB {
		return false, fmt.Errorf("argon2: memory cost %d KiB below the minimum", memory)
	}
	if len(salt) < minSaltLen {
		return false, fmt.Errorf("argon2: salt length %d below the minimum", len(salt))
	}
	if len(want) < minKeyLen {
		return false, fmt.Errorf("argon2: key length %d below the minimum", len(want))
	}
	if time == 0 || time > maxTime {
		return false, fmt.Errorf("argon2: time cost %d out of range", time)
	}
	if threads == 0 {
		return false, fmt.Errorf("argon2: parallelism must be at least 1")
	}
	if memory > maxMemoryKiB {
		return false, fmt.Errorf("argon2: memory cost %d KiB out of range", memory)
	}
	// Memory and iterations are cheap to inflate individually but multiply
	// into the actual work. Bounding the product is what keeps a mangled row
	// from turning one login into a multi-second stall.
	if work := uint64(memory) * uint64(time); work > maxWorkKiB {
		return false, fmt.Errorf("argon2: work factor %d out of range", work)
	}
	if len(salt) > maxSaltLen {
		return false, fmt.Errorf("argon2: salt length %d out of range", len(salt))
	}
	if len(want) > maxKeyLen {
		return false, fmt.Errorf("argon2: key length %d out of range", len(want))
	}
	keyLen := uint32(len(want)) //nolint:gosec // bounded by maxKeyLen just above.
	got := argon2.IDKey([]byte(secret), salt, time, memory, threads, keyLen)
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
