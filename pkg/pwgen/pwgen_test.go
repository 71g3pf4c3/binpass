package pwgen

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateLength(t *testing.T) {
	pw, err := Generate(Options{Length: 32})
	require.NoError(t, err)
	assert.Len(t, pw, 32)
}

func TestGenerateDefaultLength(t *testing.T) {
	pw, err := Generate(Options{})
	require.NoError(t, err)
	assert.Len(t, pw, 24)
}

func TestGenerateNoDigitsNoSymbols(t *testing.T) {
	pw, err := Generate(Options{Length: 100, NoDigits: true, Symbols: false})
	require.NoError(t, err)
	assert.False(t, strings.ContainsAny(pw, "0123456789"))
	assert.False(t, strings.ContainsAny(pw, "!@#$%^&*()"))
}

func TestGenerateUnique(t *testing.T) {
	a, _ := Generate(Options{Length: 32})
	b, _ := Generate(Options{Length: 32})
	assert.NotEqual(t, a, b)
}
