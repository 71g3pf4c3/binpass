// Package jwt issues and verifies Ed25519-signed access tokens for binpassd.
// It implements a minimal JWS (EdDSA) so the server has no heavyweight JWT
// dependency and full control over claims.
package jwt

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Claims are the access-token claims.
type Claims struct {
	// Subject is the user ID.
	Subject string `json:"sub"`
	// DeviceID is the authenticated device.
	DeviceID string `json:"device_id"`
	// IssuedAt is the issue time (Unix seconds).
	IssuedAt int64 `json:"iat"`
	// ExpiresAt is the expiry time (Unix seconds).
	ExpiresAt int64 `json:"exp"`
}

// header is the fixed JWS header for EdDSA.
type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// Issuer signs access tokens with an Ed25519 private key.
type Issuer struct {
	// priv is the Ed25519 signing key.
	priv ed25519.PrivateKey
	// ttl is the access-token lifetime.
	ttl time.Duration
}

// NewIssuer returns an Issuer for the given key and token TTL.
func NewIssuer(priv ed25519.PrivateKey, ttl time.Duration) *Issuer {
	return &Issuer{priv: priv, ttl: ttl}
}

// b64 is the URL-safe, unpadded base64 encoding used by JWS.
var b64 = base64.RawURLEncoding

// Issue signs a token for the user and device, returning the token and its
// expiry time.
func (i *Issuer) Issue(userID, deviceID string) (string, time.Time, error) {
	now := time.Now()
	exp := now.Add(i.ttl)
	claims := Claims{
		Subject:   userID,
		DeviceID:  deviceID,
		IssuedAt:  now.Unix(),
		ExpiresAt: exp.Unix(),
	}
	hb, err := json.Marshal(header{Alg: "EdDSA", Typ: "JWT"})
	if err != nil {
		return "", time.Time{}, err
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", time.Time{}, err
	}
	signingInput := b64.EncodeToString(hb) + "." + b64.EncodeToString(cb)
	sig := ed25519.Sign(i.priv, []byte(signingInput))
	return signingInput + "." + b64.EncodeToString(sig), exp, nil
}

// Verifier validates access tokens with an Ed25519 public key.
type Verifier struct {
	// pub is the Ed25519 verification key.
	pub ed25519.PublicKey
}

// NewVerifier returns a Verifier for the given public key.
func NewVerifier(pub ed25519.PublicKey) *Verifier { return &Verifier{pub: pub} }

// Verify checks the token signature and expiry, returning the claims.
func (v *Verifier) Verify(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("jwt: malformed token")
	}
	signingInput := parts[0] + "." + parts[1]
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("jwt: signature decode: %w", err)
	}
	if !ed25519.Verify(v.pub, []byte(signingInput), sig) {
		return nil, fmt.Errorf("jwt: bad signature")
	}
	cb, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("jwt: claims decode: %w", err)
	}
	var claims Claims
	if err := json.Unmarshal(cb, &claims); err != nil {
		return nil, fmt.Errorf("jwt: claims unmarshal: %w", err)
	}
	if time.Now().Unix() >= claims.ExpiresAt {
		return nil, fmt.Errorf("jwt: token expired")
	}
	return &claims, nil
}
