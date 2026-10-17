package secretservice

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUnpadPKCS7Vectors pins the verdict of the padding check, which was
// rewritten to run in constant time. The accepted and rejected inputs must
// be exactly the ones the branchy version accepted and rejected: a check
// that grew more permissive would turn a wrong key into a password-shaped
// return value, and one that grew stricter would reject real secrets.
func TestUnpadPKCS7Vectors(t *testing.T) {
	const blockSize = 16

	for _, tc := range []struct {
		name    string
		in      []byte
		want    []byte
		wantErr bool
	}{
		{
			name: "a full block of padding, as an aligned plaintext produces",
			in:   bytes.Repeat([]byte{0x10}, 16),
			want: []byte{},
		},
		{
			name: "a single padding byte",
			in:   append(bytes.Repeat([]byte("a"), 15), 0x01),
			want: bytes.Repeat([]byte("a"), 15),
		},
		{
			name: "five padding bytes",
			in:   append(bytes.Repeat([]byte("a"), 11), 5, 5, 5, 5, 5),
			want: bytes.Repeat([]byte("a"), 11),
		},
		{
			name: "two blocks, the second all padding",
			in:   append(bytes.Repeat([]byte("a"), 16), bytes.Repeat([]byte{0x10}, 16)...),
			want: bytes.Repeat([]byte("a"), 16),
		},
		{
			name:    "a pad count of zero",
			in:      append(bytes.Repeat([]byte("a"), 15), 0x00),
			wantErr: true,
		},
		{
			name:    "a pad count beyond the block size",
			in:      append(bytes.Repeat([]byte("a"), 31), 0x11),
			wantErr: true,
		},
		{
			name: "the last byte right and an earlier pad byte wrong",
			// The case a padding oracle probes: only the bytes before the
			// last disagree, so the verdict must not depend on where.
			in:      append(bytes.Repeat([]byte("a"), 13), 0x02, 0x03, 0x03),
			wantErr: true,
		},
		{
			name:    "nothing at all",
			in:      nil,
			wantErr: true,
		},
		{
			name:    "a length that is not a whole number of blocks",
			in:      bytes.Repeat([]byte{0x01}, 17),
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := unpadPKCS7(tc.in, blockSize)
			if tc.wantErr {
				assert.Error(t, err)
				assert.Nil(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestUnpadPKCS7RoundTripsEveryLength keeps pad and unpad in agreement,
// which is what makes a secret of any length survive the bus.
func TestUnpadPKCS7RoundTripsEveryLength(t *testing.T) {
	const blockSize = 16
	for n := 0; n <= 3*blockSize; n++ {
		plaintext := bytes.Repeat([]byte("a"), n)
		got, err := unpadPKCS7(padPKCS7(plaintext, blockSize), blockSize)
		require.NoError(t, err, "length %d", n)
		assert.Equal(t, plaintext, got, "length %d must round-trip", n)
	}
}
