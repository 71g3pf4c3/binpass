package crypto

import (
	"errors"
	"fmt"
	"io"
)

// ErrTooLarge reports input a decode path refused because of its size.
var ErrTooLarge = errors.New("crypto: input too large")

// MaxEntryBytes bounds every untrusted buffer a decryption fills.
//
// Ciphertext arrives from whoever controls the store — including a hostile
// sync remote, which can encrypt to the victim's public recipients. An entry
// is a few hundred bytes of text and the headroom here is for base64 binary
// entries, so anything past the bound is not a password: gpg decompresses
// whatever the OpenPGP packet declares (--compress-algo=none only applies
// when writing), which turns a small file into an out-of-memory kill.
const MaxEntryBytes = 16 << 20

// readLimited reads r into memory, failing rather than truncating once the
// input passes max.
//
// Truncation would be the worse answer: a silently shortened plaintext is a
// secret the caller goes on to display, type, or write back.
func readLimited(r io.Reader, max int64, what string) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%w: %s exceeds %d bytes", ErrTooLarge, what, max)
	}
	return data, nil
}
