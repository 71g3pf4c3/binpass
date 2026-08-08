// Package secret parses and serialises the pass(1) secret format.
//
// The format is deliberately minimal and identical to pass: the first line is
// the password, everything after it is free-form text. Lines shaped like
// "key: value" are additionally exposed as fields for --field lookups, and any
// line containing an otpauth:// URI is exposed as an OTP source, but neither is
// required. Round-tripping a secret through Parse and Bytes is byte-preserving.
package secret

import (
	"strings"
)

// otpScheme is the URI scheme carrying TOTP/HOTP parameters, as used by pass-otp.
const otpScheme = "otpauth://"

// Secret is a parsed store entry.
//
// Raw holds the exact bytes the entry was parsed from; all other members are
// views over it. Mutating a Secret through its methods keeps Raw consistent.
type Secret struct {
	// raw is the verbatim plaintext of the entry.
	raw []byte
}

// Parse interprets b as a pass secret. It never fails: any byte sequence is a
// valid secret, which matches pass's own behaviour.
func Parse(b []byte) *Secret {
	return &Secret{raw: b}
}

// New builds a secret from a password and an optional trailing body.
func New(password, body string) *Secret {
	var sb strings.Builder
	sb.WriteString(password)
	sb.WriteString("\n")
	if body != "" {
		sb.WriteString(body)
		if !strings.HasSuffix(body, "\n") {
			sb.WriteString("\n")
		}
	}
	return &Secret{raw: []byte(sb.String())}
}

// Bytes returns the verbatim plaintext of the secret.
func (s *Secret) Bytes() []byte { return s.raw }

// String returns the verbatim plaintext of the secret.
func (s *Secret) String() string { return string(s.raw) }

// Password returns the first line, without its line terminator.
func (s *Secret) Password() string {
	line, _, _ := strings.Cut(string(s.raw), "\n")
	return strings.TrimSuffix(line, "\r")
}

// Body returns everything after the first line, verbatim.
func (s *Secret) Body() string {
	_, rest, found := strings.Cut(string(s.raw), "\n")
	if !found {
		return ""
	}
	return rest
}

// Lines returns the secret split into lines, without terminators. A trailing
// newline does not produce a final empty element.
func (s *Secret) Lines() []string {
	t := strings.TrimSuffix(string(s.raw), "\n")
	if t == "" {
		return nil
	}
	lines := strings.Split(t, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSuffix(l, "\r")
	}
	return lines
}

// Field returns the value of the first "key: value" line whose key matches name
// case-insensitively. The password line is not considered a field.
func (s *Secret) Field(name string) (string, bool) {
	lines := s.Lines()
	if len(lines) < 2 {
		return "", false
	}
	for _, line := range lines[1:] {
		k, v, ok := splitField(line)
		if ok && strings.EqualFold(k, name) {
			return v, true
		}
	}
	return "", false
}

// Fields returns all "key: value" pairs after the password line, in order.
// Duplicate keys are preserved: pass imposes no uniqueness.
func (s *Secret) Fields() []Field {
	lines := s.Lines()
	if len(lines) < 2 {
		return nil
	}
	var out []Field
	for _, line := range lines[1:] {
		if k, v, ok := splitField(line); ok {
			out = append(out, Field{Key: k, Value: v})
		}
	}
	return out
}

// Field is a single "key: value" pair of a secret.
type Field struct {
	// Key is the field name as written, with original case.
	Key string
	// Value is the text after the first colon, space-trimmed.
	Value string
}

// OTP returns the first otpauth:// URI found anywhere in the secret, matching
// pass-otp's lookup behaviour.
func (s *Secret) OTP() (string, bool) {
	for _, uri := range s.OTPAll() {
		return uri, true
	}
	return "", false
}

// OTPAll returns every otpauth:// URI in the secret, in order of appearance.
func (s *Secret) OTPAll() []string {
	var out []string
	for _, line := range s.Lines() {
		if uri, ok := extractOTP(line); ok {
			out = append(out, uri)
		}
	}
	return out
}

// SetPassword replaces the first line, keeping the rest of the secret intact.
func (s *Secret) SetPassword(password string) {
	body := s.Body()
	*s = *New(password, body)
}

// ReplaceLineContaining returns a copy of the secret with the first occurrence
// of old replaced by replacement, leaving every other byte alone. It is how an
// advancing HOTP counter is written back without disturbing the rest of the
// entry.
func (s *Secret) ReplaceLineContaining(old, replacement string) *Secret {
	return &Secret{raw: []byte(strings.Replace(string(s.raw), old, replacement, 1))}
}

// splitField parses a "key: value" line. Keys may not contain spaces or colons,
// which keeps free-form prose from being misread as fields.
func splitField(line string) (key, value string, ok bool) {
	k, v, found := strings.Cut(line, ":")
	if !found {
		return "", "", false
	}
	k = strings.TrimSpace(k)
	if k == "" || strings.ContainsAny(k, " \t") {
		return "", "", false
	}
	// A "//" prefix means the colon belonged to a URI scheme, not a field.
	if strings.HasPrefix(v, "//") {
		return "", "", false
	}
	return k, strings.TrimSpace(v), true
}

// extractOTP returns the otpauth:// URI contained in line, if any. The URI runs
// to the first space or to end of line.
func extractOTP(line string) (string, bool) {
	i := strings.Index(line, otpScheme)
	if i < 0 {
		return "", false
	}
	uri := line[i:]
	if j := strings.IndexAny(uri, " \t"); j >= 0 {
		uri = uri[:j]
	}
	return uri, true
}
