package otp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTOTPRFC6238 checks the canonical RFC 6238 SHA1 test vectors.
func TestTOTPRFC6238(t *testing.T) {
	// RFC test seed "12345678901234567890" is base32 GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ.
	uri := "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA1&digits=8&period=30"
	k, err := Parse(uri)
	require.NoError(t, err)

	cases := []struct {
		unix int64
		want string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
	}
	for _, c := range cases {
		code, _ := k.GenerateAt(time.Unix(c.unix, 0))
		assert.Equal(t, c.want, code, "unix=%d", c.unix)
	}
}

// TestHOTPRFC4226 checks the canonical RFC 4226 test vectors.
func TestHOTPRFC4226(t *testing.T) {
	uri := "otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=6"
	want := []string{"755224", "287082", "359152", "969429", "338314"}
	for i, w := range want {
		k, err := Parse(uri)
		require.NoError(t, err)
		k.Counter = uint64(i)
		code, rem := k.Generate()
		assert.Equal(t, w, code, "counter=%d", i)
		assert.Equal(t, 0, rem)
	}
}

func TestParseErrors(t *testing.T) {
	_, err := Parse("http://x")
	assert.Error(t, err)
	_, err = Parse("otpauth://totp/x")
	assert.Error(t, err)
	_, err = Parse("otpauth://foo/x?secret=AA")
	assert.Error(t, err)
}

func TestURIRoundTrip(t *testing.T) {
	k, err := Parse("otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&period=60&digits=7")
	require.NoError(t, err)
	assert.Equal(t, "alice", k.Account)
	assert.Equal(t, "GitHub", k.Issuer)
	assert.Equal(t, 60, k.Period)
	assert.Equal(t, 7, k.Digits)

	k2, err := Parse(k.URI())
	require.NoError(t, err)
	assert.Equal(t, k.Secret, k2.Secret)
	assert.Equal(t, k.Period, k2.Period)
}
