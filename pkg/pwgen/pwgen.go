// Package pwgen generates passwords and diceware passphrases.
//
// Every generator draws from crypto/rand and rejects modulo bias, so the
// output is uniform over the requested alphabet.
package pwgen

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// DefaultLength is pass's default generated password length.
const DefaultLength = 25

// CharacterSet is the alphabet pass uses by default: printable ASCII
// alphanumerics plus punctuation.
const CharacterSet = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"

// CharacterSetNoSymbols is the alphabet used with --no-symbols.
const CharacterSetNoSymbols = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// ErrEmptyAlphabet reports a generation request with nothing to choose from.
var ErrEmptyAlphabet = errors.New("pwgen: empty character set")

// Generate returns a password of n runes drawn uniformly from alphabet.
func Generate(n int, alphabet string) (string, error) {
	if n <= 0 {
		return "", fmt.Errorf("pwgen: length must be positive, got %d", n)
	}
	runes := []rune(alphabet)
	if len(runes) == 0 {
		return "", ErrEmptyAlphabet
	}
	var sb strings.Builder
	sb.Grow(n)
	for range n {
		i, err := randIndex(len(runes))
		if err != nil {
			return "", err
		}
		sb.WriteRune(runes[i])
	}
	return sb.String(), nil
}

// Passphrase returns a diceware passphrase of n words from wordlist, joined by
// sep.
func Passphrase(n int, wordlist []string, sep string) (string, error) {
	if n <= 0 {
		return "", fmt.Errorf("pwgen: word count must be positive, got %d", n)
	}
	if len(wordlist) == 0 {
		return "", ErrEmptyAlphabet
	}
	words := make([]string, 0, n)
	for range n {
		i, err := randIndex(len(wordlist))
		if err != nil {
			return "", err
		}
		words = append(words, wordlist[i])
	}
	return strings.Join(words, sep), nil
}

// randIndex returns a uniform index in [0, n) from the system CSPRNG.
func randIndex(n int) (int, error) {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0, fmt.Errorf("pwgen: %w", err)
	}
	return int(v.Int64()), nil
}
