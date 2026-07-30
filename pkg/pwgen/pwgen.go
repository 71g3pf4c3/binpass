// Package pwgen generates cryptographically secure random passwords.
package pwgen

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// Character classes used to compose passwords.
const (
	lower   = "abcdefghijklmnopqrstuvwxyz"
	upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits  = "0123456789"
	symbols = "!@#$%^&*()-_=+[]{};:,.<>?"
)

// Options controls password generation.
type Options struct {
	// Length is the number of characters to generate.
	Length int
	// Symbols includes punctuation when true.
	Symbols bool
	// NoDigits excludes digits when true.
	NoDigits bool
}

// Generate returns a random password per opts.
func Generate(opts Options) (string, error) {
	if opts.Length <= 0 {
		opts.Length = 24
	}
	alphabet := lower + upper
	if !opts.NoDigits {
		alphabet += digits
	}
	if opts.Symbols {
		alphabet += symbols
	}
	return fromAlphabet(alphabet, opts.Length)
}

// fromAlphabet draws n uniformly random characters from alphabet.
func fromAlphabet(alphabet string, n int) (string, error) {
	out := make([]byte, n)
	max := big.NewInt(int64(len(alphabet)))
	for i := range out {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("pwgen: random: %w", err)
		}
		out[i] = alphabet[idx.Int64()]
	}
	return string(out), nil
}
