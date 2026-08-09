package argon2_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/71g3pf4c3/binpass/server/pkg/argon2"
	"github.com/stretchr/testify/require"
)

// FuzzVerify feeds malformed encoded hashes to Verify. The encoded hash comes
// from the database, so a row a migration or an operator mangled must produce
// an error rather than a panic, an enormous allocation, or a false accept.
func FuzzVerify(f *testing.F) {
	// Cheap parameters: the fuzzer runs this thousands of times, and the
	// property under test is the parser, not the cost of the KDF.
	h := argon2.New(argon2.Params{MemoryMiB: 1, Time: 1, Threads: 1, KeyLen: 16, SaltLen: 8})
	valid, err := h.Hash("correct horse")
	require.NoError(f, err)

	for _, seed := range []string{
		valid,
		"",
		"$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$a2V5",
		"$argon2id$v=19$m=0,t=0,p=0$$",
		"$argon2i$v=19$m=1,t=1,p=1$c2FsdA$a2V5",
		"$argon2id$v=19$m=1,t=1,p=1$!!!$a2V5",
		"$$$$$",
		"$argon2id$v=19$m=1,t=1,p=1$c2FsdA$",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, encoded string) {
		// Verify accepts parameters up to a bound that is deliberately
		// generous for a login; running the KDF at that cost thousands of
		// times would make the fuzzer look hung. The bound itself is
		// asserted by TestVerifyRejectsAbsurdParameters.
		if costly(encoded) {
			t.Skip("parameters too expensive to run under the fuzzer")
		}
		ok, err := argon2.Verify("correct horse", encoded)
		if err != nil {
			require.False(t, ok, "a failed verification must not report a match")
			return
		}
		if !ok {
			return
		}
		// A hash cannot match two different secrets. Comparing against the
		// hash of a known secret would be wrong here: each fuzz worker is a
		// separate process with its own salt, and workers share their corpus.
		wrong, err := argon2.Verify("wrong horse", encoded)
		require.NoError(t, err, "a hash that verified once must stay parseable")
		require.False(t, wrong, "%q matched two different secrets", encoded)
	})
}

// costly reports whether an encoded hash asks for enough work that running the
// KDF would dominate the fuzzer's time budget.
func costly(encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		return false
	}
	var memory, time uint64
	var threads uint64
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return false
	}
	// Verify's own floor is 8 MiB, so anything it accepts costs at least
	// that; only multi-iteration variants of it need skipping.
	return memory*time > 16<<10
}

// TestVerifyRejectsAbsurdParameters covers the bounds the fuzzer skips over.
// Every one of these came out of a stored hash that no longer matches what
// this build produces: a zero cost panicked inside the KDF, and a large one
// turned a single login into a stall.
func TestVerifyRejectsAbsurdParameters(t *testing.T) {
	for name, encoded := range map[string]string{
		"zero time":     "$argon2id$v=19$m=1024,t=0,p=1$MDAwMDAwMDA$MDAwMDAwMDA",
		"zero threads":  "$argon2id$v=19$m=1024,t=1,p=0$MDAwMDAwMDA$MDAwMDAwMDA",
		"huge time":     "$argon2id$v=19$m=1024,t=111116,p=1$MDAwMDAwMDA$MDAwMDAwMDA",
		"huge memory":   "$argon2id$v=19$m=4294967295,t=1,p=1$MDAwMDAwMDA$MDAwMDAwMDA",
		"huge product":  "$argon2id$v=19$m=2222220,t=9,p=1$MDAwMDAwMDA$MDAwMDAwMDA",
		"empty salt":    "$argon2id$v=19$m=1024,t=1,p=1$$MDAwMDAwMDA",
		"empty key":     "$argon2id$v=19$m=1024,t=1,p=1$MDAwMDAwMDA$",
		"wrong variant": "$argon2i$v=19$m=1024,t=1,p=1$MDAwMDAwMDA$MDAwMDAwMDA",
	} {
		t.Run(name, func(t *testing.T) {
			ok, err := argon2.Verify("correct horse", encoded)
			require.Error(t, err, "must be refused rather than run")
			require.False(t, ok)
		})
	}
}

// TestVerifyRejectsWeakParameters covers the lower bounds. A hash naming a
// one-byte key matched roughly one secret in 256, so a mangled row was not
// merely a crash but a way past the password check.
func TestVerifyRejectsWeakParameters(t *testing.T) {
	for name, encoded := range map[string]string{
		"one-byte key":  "$argon2id$v=19$m=1048576,t=4,p=2$MTBQUFBQUFBQ$00",
		"zero memory":   "$argon2id$v=19$m=0,t=4,p=2$MTBQUFBQUFBQ$MDAwMDAwMDAwMDAwMDAwMA",
		"tiny memory":   "$argon2id$v=19$m=8,t=4,p=2$MTBQUFBQUFBQ$MDAwMDAwMDAwMDAwMDAwMA",
		"one-byte salt": "$argon2id$v=19$m=1048576,t=4,p=2$MA$MDAwMDAwMDAwMDAwMDAwMA",
	} {
		t.Run(name, func(t *testing.T) {
			ok, err := argon2.Verify("correct horse", encoded)
			require.Error(t, err)
			require.False(t, ok)
		})
	}
}

// TestDefaultParametersSurviveVerification guards the bounds against being
// tightened past the parameters this build actually writes.
func TestDefaultParametersSurviveVerification(t *testing.T) {
	h := argon2.New(argon2.Default())
	encoded, err := h.Hash("correct horse")
	require.NoError(t, err)

	ok, err := argon2.Verify("correct horse", encoded)
	require.NoError(t, err, "a hash from Default() must verify")
	require.True(t, ok)

	ok, err = argon2.Verify("wrong horse", encoded)
	require.NoError(t, err)
	require.False(t, ok)
}
