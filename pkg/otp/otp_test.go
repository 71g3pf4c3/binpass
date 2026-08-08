package otp_test

import (
	"testing"
	"time"

	"github.com/71g3pf4c3/binpass/pkg/otp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rfcSecret is the ASCII string "12345678901234567890", the key used by the
// RFC 4226 and RFC 6238 test vectors, encoded in base32.
const rfcSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func TestHOTPMatchesRFC4226(t *testing.T) {
	// RFC 4226, Appendix D.
	want := []string{
		"755224", "287082", "359152", "969429", "338314",
		"254676", "287922", "162583", "399871", "520489",
	}
	for counter, code := range want {
		cfg, err := otp.Parse("otpauth://hotp/test?secret=" + rfcSecret + "&counter=" + itoa(counter))
		require.NoError(t, err)

		got, err := cfg.Code(time.Time{})
		require.NoError(t, err)
		assert.Equal(t, code, got, "counter %d", counter)
	}
}

func TestTOTPMatchesRFC6238(t *testing.T) {
	// RFC 6238, Appendix B. The 8-digit vectors pin both the time step and
	// the truncation.
	tests := []struct {
		unix int64
		algo string
		want string
	}{
		{59, "SHA1", "94287082"},
		{1111111109, "SHA1", "07081804"},
		{1111111111, "SHA1", "14050471"},
		{1234567890, "SHA1", "89005924"},
		{2000000000, "SHA1", "69279037"},
		{20000000000, "SHA1", "65353130"},
	}
	for _, tc := range tests {
		cfg, err := otp.Parse("otpauth://totp/test?secret=" + rfcSecret + "&digits=8&algorithm=" + tc.algo)
		require.NoError(t, err)

		got, err := cfg.Code(time.Unix(tc.unix, 0))
		require.NoError(t, err)
		assert.Equal(t, tc.want, got, "at %d", tc.unix)
	}
}

func TestParseExtractsMetadata(t *testing.T) {
	cfg, err := otp.Parse("otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&period=60&digits=8")
	require.NoError(t, err)

	assert.Equal(t, otp.TOTP, cfg.Kind)
	assert.Equal(t, "GitHub", cfg.Issuer)
	assert.Equal(t, "alice", cfg.Account)
	assert.Equal(t, 60*time.Second, cfg.Period)
	assert.Equal(t, 8, cfg.Digits)
}

func TestParseAcceptsUnpaddedAndSpacedSecrets(t *testing.T) {
	// Providers print secrets in groups, and often without padding.
	cfg, err := otp.Parse("otpauth://totp/x?secret=jbsw%20y3dp%20ehpk%203pxp")
	require.NoError(t, err)
	assert.NotEmpty(t, cfg.Secret)
}

func TestParseRejectsBadURIs(t *testing.T) {
	for _, uri := range []string{
		"https://example.com",
		"otpauth://unknown/x?secret=" + rfcSecret,
		"otpauth://totp/x",
		"otpauth://totp/x?secret=not-base32!",
		"otpauth://totp/x?secret=" + rfcSecret + "&digits=99",
		"otpauth://totp/x?secret=" + rfcSecret + "&period=0",
	} {
		_, err := otp.Parse(uri)
		assert.Error(t, err, "uri %q must be rejected", uri)
	}
}

func TestExpires(t *testing.T) {
	cfg, err := otp.Parse("otpauth://totp/x?secret=" + rfcSecret)
	require.NoError(t, err)

	at := time.Unix(1000, 0)
	assert.Equal(t, time.Unix(1020, 0), cfg.Expires(at), "codes expire on the next 30 second boundary")
}

func TestNextAdvancesCounterWithoutMutating(t *testing.T) {
	cfg, err := otp.Parse("otpauth://hotp/x?secret=" + rfcSecret + "&counter=5")
	require.NoError(t, err)

	next := cfg.Next()
	assert.Equal(t, uint64(5), cfg.Counter, "the original is untouched")
	assert.Equal(t, uint64(6), next.Counter)

	before, err := cfg.Code(time.Time{})
	require.NoError(t, err)
	after, err := next.Code(time.Time{})
	require.NoError(t, err)
	assert.NotEqual(t, before, after, "advancing the counter must change the code")
}

func FuzzParse(f *testing.F) {
	f.Add("otpauth://totp/x?secret=" + rfcSecret)
	f.Add("otpauth://hotp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&counter=1")
	f.Add("")
	f.Fuzz(func(t *testing.T, uri string) {
		cfg, err := otp.Parse(uri)
		if err != nil {
			return
		}
		// Anything that parses must also produce a code of the promised size.
		code, err := cfg.Code(time.Unix(1234567890, 0))
		if err != nil {
			return
		}
		if len(code) != cfg.Digits {
			t.Fatalf("code %q does not have %d digits", code, cfg.Digits)
		}
	})
}

// itoa renders a small non-negative integer.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf []byte
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	return string(buf)
}
