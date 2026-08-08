package pwgen_test

import (
	"strings"
	"testing"

	"github.com/71g3pf4c3/binpass/pkg/pwgen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateLengthAndAlphabet(t *testing.T) {
	got, err := pwgen.Generate(32, "abc")
	require.NoError(t, err)
	assert.Len(t, got, 32)
	for _, r := range got {
		assert.Contains(t, "abc", string(r))
	}
}

func TestGenerateIsRandom(t *testing.T) {
	seen := make(map[string]bool)
	for range 50 {
		got, err := pwgen.Generate(pwgen.DefaultLength, pwgen.CharacterSet)
		require.NoError(t, err)
		assert.False(t, seen[got], "generated the same password twice")
		seen[got] = true
	}
}

func TestGenerateCoversTheWholeAlphabet(t *testing.T) {
	// With 4000 draws over 3 symbols, a missing symbol means a broken
	// generator rather than bad luck.
	counts := map[rune]int{}
	for range 4000 {
		got, err := pwgen.Generate(1, "abc")
		require.NoError(t, err)
		counts[rune(got[0])]++
	}
	for _, r := range "abc" {
		assert.Positive(t, counts[r], "symbol %q was never generated", r)
	}
}

func TestGenerateRejectsBadInput(t *testing.T) {
	_, err := pwgen.Generate(0, "abc")
	assert.Error(t, err)

	_, err = pwgen.Generate(-1, "abc")
	assert.Error(t, err)

	_, err = pwgen.Generate(8, "")
	assert.ErrorIs(t, err, pwgen.ErrEmptyAlphabet)
}

func TestGenerateHandlesMultibyteAlphabets(t *testing.T) {
	got, err := pwgen.Generate(6, "мир")
	require.NoError(t, err)
	assert.Equal(t, 6, len([]rune(got)), "length counts runes, not bytes")
}

func TestPassphrase(t *testing.T) {
	words := []string{"correct", "horse", "battery", "staple"}
	got, err := pwgen.Passphrase(5, words, "-")
	require.NoError(t, err)
	assert.Len(t, strings.Split(got, "-"), 5)
	for _, w := range strings.Split(got, "-") {
		assert.Contains(t, words, w)
	}
}

func TestPassphraseRejectsBadInput(t *testing.T) {
	_, err := pwgen.Passphrase(0, []string{"a"}, "-")
	assert.Error(t, err)

	_, err = pwgen.Passphrase(3, nil, "-")
	assert.ErrorIs(t, err, pwgen.ErrEmptyAlphabet)
}

func TestExpandCharacterSet(t *testing.T) {
	tests := []struct {
		name string
		spec string
		want string
	}{
		{"pass default", "[:punct:][:alnum:]", pwgen.ExpandCharacterSet("[:punct:]") + pwgen.ExpandCharacterSet("[:alnum:]")},
		{"digits only", "[:digit:]", "0123456789"},
		{"literal", "abc", "abc"},
		{"mixed", "[:digit:]xyz", "0123456789xyz"},
		{"unknown class is dropped", "[:nope:]abc", "abc"},
		{"empty", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, pwgen.ExpandCharacterSet(tc.spec))
		})
	}
}

func TestExpandCharacterSetDeduplicates(t *testing.T) {
	got := pwgen.ExpandCharacterSet("[:alnum:][:digit:]")
	assert.Equal(t, len(got), len(dedupeRunes(got)), "no symbol appears twice")
	assert.Contains(t, got, "0")
}

func TestExpandedDefaultMatchesPassAlphabet(t *testing.T) {
	got := pwgen.ExpandCharacterSet("[:punct:][:alnum:]")
	assert.ElementsMatch(t, []rune(pwgen.CharacterSet), []rune(got),
		"the expanded default must be exactly pass's alphabet")
}

// dedupeRunes returns s with repeated runes removed.
func dedupeRunes(s string) string {
	seen := map[rune]bool{}
	var sb strings.Builder
	for _, r := range s {
		if !seen[r] {
			seen[r] = true
			sb.WriteRune(r)
		}
	}
	return sb.String()
}
