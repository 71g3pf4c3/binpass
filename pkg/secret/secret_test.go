package secret

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseLogin(t *testing.T) {
	in := "hunter2\n" +
		"otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub\n" +
		"url: https://github.com\n" +
		"username: alice\n" +
		"free form line\n"
	s, err := Parse([]byte(in))
	require.NoError(t, err)
	assert.Equal(t, KindLogin, s.Kind)
	assert.Equal(t, "hunter2", s.Password)
	require.Len(t, s.OTP, 1)
	u, ok := s.Get("url")
	assert.True(t, ok)
	assert.Equal(t, "https://github.com", u)
	un, ok := s.Get("USERNAME")
	assert.True(t, ok)
	assert.Equal(t, "alice", un)
	assert.Equal(t, "free form line", s.Body)
}

func TestParseTypedCard(t *testing.T) {
	in := "BINPASS-SECRET-1.0\n" +
		"Type: card\n" +
		"Bank: Tinkoff\n" +
		"Number: 5536 9138 0000 0000\n" +
		"\n" +
		"a note\n"
	s, err := Parse([]byte(in))
	require.NoError(t, err)
	assert.Equal(t, KindCard, s.Kind)
	bank, _ := s.Get("Bank")
	assert.Equal(t, "Tinkoff", bank)
	assert.Equal(t, "a note", s.Body)
}

func TestRoundTripLogin(t *testing.T) {
	s := &Secret{Kind: KindLogin, Password: "pw"}
	s.Set("username", "alice")
	s.AddOTP("otpauth://totp/x?secret=AAAA")
	out, err := Parse(s.Bytes())
	require.NoError(t, err)
	assert.Equal(t, "pw", out.Password)
	un, _ := out.Get("username")
	assert.Equal(t, "alice", un)
	require.Len(t, out.OTP, 1)
}

func TestRoundTripTyped(t *testing.T) {
	s := &Secret{Kind: KindCard}
	s.Set("Bank", "T")
	s.Body = "note"
	out, err := Parse(s.Bytes())
	require.NoError(t, err)
	assert.Equal(t, KindCard, out.Kind)
	assert.Equal(t, "note", out.Body)
}

func TestSetReplaces(t *testing.T) {
	s := &Secret{Kind: KindLogin}
	s.Set("k", "v1")
	s.Set("K", "v2")
	require.Len(t, s.Fields, 1)
	v, _ := s.Get("k")
	assert.Equal(t, "v2", v)
}

func TestParseEmpty(t *testing.T) {
	s, err := Parse(nil)
	require.NoError(t, err)
	assert.Equal(t, "", s.Password)
}

func FuzzParse(f *testing.F) {
	f.Add("hunter2\nurl: x\n")
	f.Add("BINPASS-SECRET-1.0\nType: card\n")
	f.Fuzz(func(t *testing.T, data string) {
		s, err := Parse([]byte(data))
		if err != nil {
			return
		}
		// Serialising and reparsing must not error.
		_, err = Parse(s.Bytes())
		require.NoError(t, err)
	})
}
