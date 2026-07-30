// Package otp implements TOTP (RFC 6238) and HOTP (RFC 4226) generation
// and otpauth:// URI parsing, compatible with pass-otp.
package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Algorithm identifies the HMAC hash used for code derivation.
type Algorithm string

// Supported OTP hash algorithms.
const (
	// AlgSHA1 is the default RFC-recommended algorithm.
	AlgSHA1 Algorithm = "SHA1"
	// AlgSHA256 uses SHA-256.
	AlgSHA256 Algorithm = "SHA256"
	// AlgSHA512 uses SHA-512.
	AlgSHA512 Algorithm = "SHA512"
)

// Type distinguishes time-based from counter-based OTPs.
type Type string

// OTP types.
const (
	// TypeTOTP is time-based.
	TypeTOTP Type = "totp"
	// TypeHOTP is counter-based.
	TypeHOTP Type = "hotp"
)

// Key is a parsed otpauth:// configuration.
type Key struct {
	// Type is totp or hotp.
	Type Type
	// Issuer is the optional service issuer.
	Issuer string
	// Account is the account label.
	Account string
	// Secret is the raw decoded shared secret.
	Secret []byte
	// Algorithm is the HMAC hash algorithm.
	Algorithm Algorithm
	// Digits is the number of code digits (6-8).
	Digits int
	// Period is the TOTP step in seconds.
	Period int
	// Counter is the HOTP moving factor.
	Counter uint64
}

// hasher returns a hash constructor for the key algorithm.
func (k *Key) hasher() func() hash.Hash {
	switch k.Algorithm {
	case AlgSHA256:
		return sha256.New
	case AlgSHA512:
		return sha512.New
	default:
		return sha1.New
	}
}

// Parse decodes an otpauth:// URI into a Key.
func Parse(uri string) (*Key, error) {
	u, err := url.Parse(strings.TrimSpace(uri))
	if err != nil {
		return nil, fmt.Errorf("otp: parse uri: %w", err)
	}
	if u.Scheme != "otpauth" {
		return nil, fmt.Errorf("otp: unsupported scheme %q", u.Scheme)
	}
	k := &Key{
		Type:      Type(strings.ToLower(u.Host)),
		Algorithm: AlgSHA1,
		Digits:    6,
		Period:    30,
	}
	if k.Type != TypeTOTP && k.Type != TypeHOTP {
		return nil, fmt.Errorf("otp: unknown type %q", u.Host)
	}

	label := strings.TrimPrefix(u.Path, "/")
	if i := strings.Index(label, ":"); i >= 0 {
		k.Issuer = label[:i]
		k.Account = label[i+1:]
	} else {
		k.Account = label
	}

	q := u.Query()
	secretStr := strings.ToUpper(strings.TrimSpace(q.Get("secret")))
	if secretStr == "" {
		return nil, fmt.Errorf("otp: missing secret")
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimRight(secretStr, "="))
	if err != nil {
		return nil, fmt.Errorf("otp: decode secret: %w", err)
	}
	k.Secret = secret

	if v := q.Get("issuer"); v != "" {
		k.Issuer = v
	}
	if v := q.Get("algorithm"); v != "" {
		k.Algorithm = Algorithm(strings.ToUpper(v))
	}
	if v := q.Get("digits"); v != "" {
		if d, err := strconv.Atoi(v); err == nil {
			k.Digits = d
		}
	}
	if v := q.Get("period"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			k.Period = p
		}
	}
	if v := q.Get("counter"); v != "" {
		if c, err := strconv.ParseUint(v, 10, 64); err == nil {
			k.Counter = c
		}
	}
	return k, nil
}

// URI renders the key back to an otpauth:// string.
func (k *Key) URI() string {
	label := k.Account
	if k.Issuer != "" {
		label = k.Issuer + ":" + k.Account
	}
	q := url.Values{}
	q.Set("secret", base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(k.Secret))
	if k.Issuer != "" {
		q.Set("issuer", k.Issuer)
	}
	q.Set("algorithm", string(k.Algorithm))
	q.Set("digits", strconv.Itoa(k.Digits))
	if k.Type == TypeTOTP {
		q.Set("period", strconv.Itoa(k.Period))
	} else {
		q.Set("counter", strconv.FormatUint(k.Counter, 10))
	}
	u := url.URL{Scheme: "otpauth", Host: string(k.Type), Path: "/" + label, RawQuery: q.Encode()}
	return u.String()
}

// hotp computes the code for a specific counter value.
func (k *Key) hotp(counter uint64) string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)
	mac := hmac.New(k.hasher(), k.Secret)
	mac.Write(buf)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	mod := uint32(1)
	for i := 0; i < k.Digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", k.Digits, value%mod)
}

// Generate returns the current OTP code and, for TOTP, the seconds remaining
// in the current step (0 for HOTP).
func (k *Key) Generate() (code string, remaining int) {
	return k.GenerateAt(time.Now())
}

// GenerateAt returns the OTP code valid at t (used for testing).
func (k *Key) GenerateAt(t time.Time) (code string, remaining int) {
	if k.Type == TypeHOTP {
		return k.hotp(k.Counter), 0
	}
	period := k.Period
	if period <= 0 {
		period = 30
	}
	counter := uint64(t.Unix() / int64(period))
	rem := period - int(t.Unix()%int64(period))
	return k.hotp(counter), rem
}
