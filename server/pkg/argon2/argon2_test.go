package argon2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fast returns cheap params so tests stay quick.
func fast() Params { return Params{MemoryMiB: 8, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16} }

func TestHashVerify(t *testing.T) {
	h := New(fast())
	enc, err := h.Hash("secret")
	require.NoError(t, err)

	ok, err := Verify("secret", enc)
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = Verify("wrong", enc)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestHashUniqueSalt(t *testing.T) {
	h := New(fast())
	a, _ := h.Hash("secret")
	b, _ := h.Hash("secret")
	assert.NotEqual(t, a, b)
}

func TestVerifyMalformed(t *testing.T) {
	_, err := Verify("secret", "not-a-hash")
	assert.Error(t, err)
}

func TestDefault(t *testing.T) {
	p := Default()
	assert.Equal(t, uint32(256), p.MemoryMiB)
	assert.Equal(t, uint32(3), p.Time)
}
