// Package secret parses and serialises the binpass secret format.
//
// A secret is compatible with pass/gopass: the first line is the password,
// followed by either "key: value" lines, otpauth:// URIs, or a typed
// GOPASS-SECRET/BINPASS-SECRET header block. Typed secrets carry a Type
// (login|text|binary|card|otp) plus arbitrary X-* metadata headers.
package secret

import (
	"bufio"
	"bytes"
	"fmt"
	"sort"
	"strings"
)

// Kind enumerates the supported secret types.
type Kind string

// Supported secret kinds.
const (
	// KindLogin is the default kind: password plus key/value fields.
	KindLogin Kind = "login"
	// KindText is free-form text with no structured password semantics.
	KindText Kind = "text"
	// KindBinary is a base64-encoded binary payload.
	KindBinary Kind = "binary"
	// KindCard is a typed bank card secret.
	KindCard Kind = "card"
	// KindOTP is a standalone one-time-password secret.
	KindOTP Kind = "otp"
)

// binpassHeader is the marker for a typed binpass secret block.
const binpassHeader = "BINPASS-SECRET-1.0"

// gopassHeader is the compatible gopass typed-secret marker.
const gopassHeader = "GOPASS-SECRET-1.0"

// Secret is a parsed representation of a stored entry.
type Secret struct {
	// Kind is the secret type; defaults to KindLogin.
	Kind Kind
	// Password is the first line of a login/card secret (may be empty).
	Password string
	// Fields holds ordered key/value metadata (case-insensitive keys).
	Fields []Field
	// Body is free-form text following the header block or fields.
	Body string
	// OTP holds otpauth:// URIs found in the secret.
	OTP []string
	// typed marks that the secret was written as a typed header block.
	typed bool
}

// Field is a single ordered key/value pair of a secret.
type Field struct {
	// Key is the field name as written (original case preserved).
	Key string
	// Value is the field value.
	Value string
}

// Get returns the first value for key, matched case-insensitively.
func (s *Secret) Get(key string) (string, bool) {
	for _, f := range s.Fields {
		if strings.EqualFold(f.Key, key) {
			return f.Value, true
		}
	}
	return "", false
}

// Set replaces the value for key (case-insensitive) or appends a new field.
func (s *Secret) Set(key, value string) {
	for i := range s.Fields {
		if strings.EqualFold(s.Fields[i].Key, key) {
			s.Fields[i].Value = value
			return
		}
	}
	s.Fields = append(s.Fields, Field{Key: key, Value: value})
}

// AddOTP appends an otpauth:// URI to the secret.
func (s *Secret) AddOTP(uri string) {
	s.OTP = append(s.OTP, uri)
}

// isTypedHeader reports whether line is a recognised typed-secret marker.
func isTypedHeader(line string) bool {
	line = strings.TrimSpace(line)
	return line == binpassHeader || line == gopassHeader
}

// Parse decodes raw secret bytes into a Secret.
func Parse(data []byte) (*Secret, error) {
	s := &Secret{Kind: KindLogin}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)

	lines := make([]string, 0, 16)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("secret: read: %w", err)
	}
	if len(lines) == 0 {
		return s, nil
	}

	if isTypedHeader(lines[0]) {
		return parseTyped(s, lines[1:])
	}
	return parseLogin(s, lines)
}

// parseLogin decodes the classic pass layout: password then fields/body.
func parseLogin(s *Secret, lines []string) (*Secret, error) {
	s.Password = lines[0]
	var body []string
	inBody := false
	for _, line := range lines[1:] {
		if inBody {
			body = append(body, line)
			continue
		}
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "otpauth://") {
			s.OTP = append(s.OTP, strings.TrimSpace(line))
			continue
		}
		if k, v, ok := splitField(line); ok {
			s.Fields = append(s.Fields, Field{Key: k, Value: v})
			continue
		}
		// First non-field line starts the free-form body.
		inBody = true
		body = append(body, line)
	}
	s.Body = strings.Join(body, "\n")
	return s, nil
}

// parseTyped decodes a typed header block followed by an optional body.
func parseTyped(s *Secret, lines []string) (*Secret, error) {
	s.typed = true
	i := 0
	for ; i < len(lines); i++ {
		line := lines[i]
		if strings.TrimSpace(line) == "" {
			i++
			break
		}
		k, v, ok := splitField(line)
		if !ok {
			return nil, fmt.Errorf("secret: malformed typed header line %q", line)
		}
		switch strings.ToLower(k) {
		case "type":
			s.Kind = Kind(strings.ToLower(strings.TrimSpace(v)))
		case "password":
			s.Password = v
		case "otpauth", "otp":
			s.OTP = append(s.OTP, v)
		default:
			s.Fields = append(s.Fields, Field{Key: k, Value: v})
		}
	}
	if i < len(lines) {
		s.Body = strings.Join(lines[i:], "\n")
	}
	return s, nil
}

// splitField splits "key: value"; ok is false if there is no colon key.
func splitField(line string) (key, value string, ok bool) {
	idx := strings.Index(line, ":")
	if idx <= 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:idx])
	if key == "" || strings.ContainsAny(key, " \t") && !validKey(key) {
		return "", "", false
	}
	value = strings.TrimSpace(line[idx+1:])
	return key, value, true
}

// validKey reports whether key looks like a header key rather than prose.
func validKey(key string) bool {
	for _, r := range key {
		if r == ' ' || r == '\t' {
			return false
		}
	}
	return true
}

// Bytes serialises the secret back to its on-disk representation.
func (s *Secret) Bytes() []byte {
	var b strings.Builder
	if s.typed || s.Kind != KindLogin {
		return s.bytesTyped()
	}
	b.WriteString(s.Password)
	b.WriteString("\n")
	for _, uri := range s.OTP {
		b.WriteString(uri)
		b.WriteString("\n")
	}
	for _, f := range s.Fields {
		b.WriteString(f.Key)
		b.WriteString(": ")
		b.WriteString(f.Value)
		b.WriteString("\n")
	}
	if s.Body != "" {
		b.WriteString(s.Body)
		if !strings.HasSuffix(s.Body, "\n") {
			b.WriteString("\n")
		}
	}
	return []byte(b.String())
}

// bytesTyped serialises a typed secret with a BINPASS-SECRET header block.
func (s *Secret) bytesTyped() []byte {
	var b strings.Builder
	b.WriteString(binpassHeader)
	b.WriteString("\n")
	b.WriteString("Type: ")
	if s.Kind == "" {
		b.WriteString(string(KindLogin))
	} else {
		b.WriteString(string(s.Kind))
	}
	b.WriteString("\n")
	if s.Password != "" {
		b.WriteString("Password: ")
		b.WriteString(s.Password)
		b.WriteString("\n")
	}
	for _, uri := range s.OTP {
		b.WriteString("Otpauth: ")
		b.WriteString(uri)
		b.WriteString("\n")
	}
	for _, f := range s.Fields {
		b.WriteString(f.Key)
		b.WriteString(": ")
		b.WriteString(f.Value)
		b.WriteString("\n")
	}
	if s.Body != "" {
		b.WriteString("\n")
		b.WriteString(s.Body)
		if !strings.HasSuffix(s.Body, "\n") {
			b.WriteString("\n")
		}
	}
	return []byte(b.String())
}

// SortedFields returns fields ordered by key for deterministic display.
func (s *Secret) SortedFields() []Field {
	out := append([]Field(nil), s.Fields...)
	sort.SliceStable(out, func(i, j int) bool {
		return strings.ToLower(out[i].Key) < strings.ToLower(out[j].Key)
	})
	return out
}
