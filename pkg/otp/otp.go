// Package otp implements the one-time password schemes carried in otpauth://
// URIs: TOTP (RFC 6238) and HOTP (RFC 4226).
package otp

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // HMAC-SHA1 is mandated by RFC 4226.
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Kind distinguishes time-based from counter-based one-time passwords.
type Kind string

// Supported OTP kinds.
const (
	// TOTP is the time-based scheme.
	TOTP Kind = "totp"
	// HOTP is the counter-based scheme.
	HOTP Kind = "hotp"
)

// Config is a parsed otpauth:// URI.
type Config struct {
	// Kind is totp or hotp.
	Kind Kind
	// Secret is the shared key, already base32-decoded.
	Secret []byte
	// Digits is the length of the generated code, normally 6.
	Digits int
	// Period is the TOTP time step.
	Period time.Duration
	// Counter is the HOTP counter.
	Counter uint64
	// Algorithm names the HMAC hash: SHA1, SHA256 or SHA512.
	Algorithm string
	// Issuer is the service the code belongs to, for display.
	Issuer string
	// Account is the account name, for display.
	Account string
}

// Parse interprets an otpauth:// URI.
func Parse(uri string) (*Config, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("otp: %w", err)
	}
	if u.Scheme != "otpauth" {
		return nil, fmt.Errorf("otp: not an otpauth URI: %q", uri)
	}

	cfg := &Config{
		Kind:      Kind(strings.ToLower(u.Host)),
		Digits:    6,
		Period:    30 * time.Second,
		Algorithm: "SHA1",
	}
	if cfg.Kind != TOTP && cfg.Kind != HOTP {
		return nil, fmt.Errorf("otp: unsupported type %q", u.Host)
	}

	label := strings.TrimPrefix(u.Path, "/")
	if issuer, account, found := strings.Cut(label, ":"); found {
		cfg.Issuer, cfg.Account = issuer, strings.TrimSpace(account)
	} else {
		cfg.Account = label
	}

	q := u.Query()
	secret := strings.ToUpper(strings.ReplaceAll(q.Get("secret"), " ", ""))
	if secret == "" {
		return nil, fmt.Errorf("otp: %q has no secret", uri)
	}
	// Authenticator secrets are commonly written without padding.
	cfg.Secret, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimRight(secret, "="))
	if err != nil {
		return nil, fmt.Errorf("otp: bad secret: %w", err)
	}

	if v := q.Get("issuer"); v != "" {
		cfg.Issuer = v
	}
	if v := q.Get("algorithm"); v != "" {
		cfg.Algorithm = strings.ToUpper(v)
	}
	if v := q.Get("digits"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 6 || n > 10 {
			return nil, fmt.Errorf("otp: bad digits %q", v)
		}
		cfg.Digits = n
	}
	if v := q.Get("period"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("otp: bad period %q", v)
		}
		cfg.Period = time.Duration(n) * time.Second
	}
	if v := q.Get("counter"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("otp: bad counter %q", v)
		}
		cfg.Counter = n
	}
	return cfg, nil
}

// Code returns the one-time password for the given moment. For HOTP the time
// is ignored and the configured counter is used.
func (c *Config) Code(at time.Time) (string, error) {
	counter := c.Counter
	if c.Kind == TOTP {
		// Times before the epoch have no meaning for TOTP, and a negative
		// Unix time would wrap into an enormous counter.
		seconds := at.Unix()
		if seconds < 0 {
			return "", fmt.Errorf("otp: time %s precedes the Unix epoch", at)
		}
		step := int64(c.Period.Seconds())
		counter = uint64(seconds / step) //nolint:gosec // seconds is non-negative and step is positive.
	}
	return c.codeAt(counter)
}

// codeAt computes the HOTP value of a counter, the primitive both schemes use.
func (c *Config) codeAt(counter uint64) (string, error) {
	newHash, err := c.hash()
	if err != nil {
		return "", err
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(newHash, c.Secret)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	// Dynamic truncation, RFC 4226 §5.3.
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	mod := uint32(math.Pow10(c.Digits))
	return fmt.Sprintf("%0*d", c.Digits, value%mod), nil
}

// hash returns the constructor for the configured HMAC hash.
func (c *Config) hash() (func() hash.Hash, error) {
	switch c.Algorithm {
	case "SHA1", "":
		return sha1.New, nil
	case "SHA256":
		return sha256.New, nil
	case "SHA512":
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("otp: unsupported algorithm %q", c.Algorithm)
	}
}

// Expires returns when the current TOTP code stops being valid.
func (c *Config) Expires(at time.Time) time.Time {
	if c.Kind != TOTP {
		return time.Time{}
	}
	step := int64(c.Period.Seconds())
	return time.Unix((at.Unix()/step+1)*step, 0)
}

// Next returns a copy of the configuration with the HOTP counter advanced.
// Callers must store the result, or the code would repeat.
func (c *Config) Next() *Config {
	next := *c
	next.Counter++
	return &next
}
