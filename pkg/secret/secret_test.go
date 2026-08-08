package secret_test

import (
	"testing"

	"github.com/71g3pf4c3/binpass/pkg/secret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sample = `hunter2
otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub
url: https://github.com
username: alice
some free form prose: with a colon
`

func TestPasswordAndBody(t *testing.T) {
	tests := []struct {
		name string
		in   string
		pass string
		body string
	}{
		{"full", sample, "hunter2", sample[len("hunter2\n"):]},
		{"password only", "hunter2\n", "hunter2", ""},
		{"no trailing newline", "hunter2", "hunter2", ""},
		{"empty", "", "", ""},
		{"empty password with body", "\nnote\n", "", "note\n"},
		{"crlf", "hunter2\r\nurl: x\r\n", "hunter2", "url: x\r\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := secret.Parse([]byte(tc.in))
			assert.Equal(t, tc.pass, s.Password())
			assert.Equal(t, tc.body, s.Body())
		})
	}
}

func TestParseIsByteExact(t *testing.T) {
	for _, in := range []string{sample, "", "\n", "a", "a\nb", "\x00\xff binary"} {
		assert.Equal(t, in, secret.Parse([]byte(in)).String())
	}
}

func TestField(t *testing.T) {
	s := secret.Parse([]byte(sample))

	v, ok := s.Field("username")
	require.True(t, ok)
	assert.Equal(t, "alice", v)

	v, ok = s.Field("URL")
	require.True(t, ok, "field lookup is case-insensitive")
	assert.Equal(t, "https://github.com", v)

	_, ok = s.Field("missing")
	assert.False(t, ok)
}

func TestFieldIgnoresPasswordLine(t *testing.T) {
	s := secret.Parse([]byte("password: notafield\nuser: alice\n"))
	_, ok := s.Field("password")
	assert.False(t, ok, "the first line is the password, never a field")
}

func TestFieldsSkipsProseAndURIs(t *testing.T) {
	s := secret.Parse([]byte(sample))
	fields := s.Fields()
	require.Len(t, fields, 2)
	assert.Equal(t, "url", fields[0].Key)
	assert.Equal(t, "username", fields[1].Key)
}

func TestFieldsPreservesDuplicates(t *testing.T) {
	s := secret.Parse([]byte("pw\nuser: a\nuser: b\n"))
	fields := s.Fields()
	require.Len(t, fields, 2)
	assert.Equal(t, "a", fields[0].Value)
	assert.Equal(t, "b", fields[1].Value)

	v, ok := s.Field("user")
	require.True(t, ok)
	assert.Equal(t, "a", v, "first match wins")
}

func TestOTP(t *testing.T) {
	s := secret.Parse([]byte(sample))
	uri, ok := s.OTP()
	require.True(t, ok)
	assert.Equal(t, "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub", uri)
}

func TestOTPAnywhereInLine(t *testing.T) {
	s := secret.Parse([]byte("pw\notp: otpauth://totp/x?secret=AA trailing words\n"))
	uri, ok := s.OTP()
	require.True(t, ok)
	assert.Equal(t, "otpauth://totp/x?secret=AA", uri, "URI ends at the first space")
}

func TestOTPAbsent(t *testing.T) {
	_, ok := secret.Parse([]byte("pw\nurl: x\n")).OTP()
	assert.False(t, ok)
}

func TestSetPasswordKeepsBody(t *testing.T) {
	s := secret.Parse([]byte(sample))
	s.SetPassword("new-password")
	assert.Equal(t, "new-password", s.Password())
	assert.Equal(t, sample[len("hunter2\n"):], s.Body())
}

func TestNew(t *testing.T) {
	assert.Equal(t, "pw\n", secret.New("pw", "").String())
	assert.Equal(t, "pw\nbody\n", secret.New("pw", "body").String())
	assert.Equal(t, "pw\nbody\n", secret.New("pw", "body\n").String(), "body newline is not doubled")
}

func TestLines(t *testing.T) {
	assert.Nil(t, secret.Parse(nil).Lines())
	assert.Equal(t, []string{"a", "b"}, secret.Parse([]byte("a\nb\n")).Lines())
	assert.Equal(t, []string{"a", "b"}, secret.Parse([]byte("a\nb")).Lines())
}

func FuzzParse(f *testing.F) {
	f.Add(sample)
	f.Add("")
	f.Add("pw\n")
	f.Add("\x00\xff")
	f.Fuzz(func(t *testing.T, in string) {
		s := secret.Parse([]byte(in))
		require.Equal(t, in, s.String(), "parse must be byte-preserving")
		s.Password()
		s.Body()
		s.Fields()
		s.OTPAll()
	})
}
