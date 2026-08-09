package jwt

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIssueVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	iss := NewIssuer(priv, time.Hour)
	token, exp, err := iss.Issue("user-1", "device-1")
	require.NoError(t, err)
	assert.True(t, exp.After(time.Now()))

	claims, err := NewVerifier(pub).Verify(token)
	require.NoError(t, err)
	assert.Equal(t, "user-1", claims.Subject)
	assert.Equal(t, "device-1", claims.DeviceID)
}

func TestVerifyExpired(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	token, _, err := NewIssuer(priv, -time.Minute).Issue("u", "d")
	require.NoError(t, err)
	_, err = NewVerifier(pub).Verify(token)
	assert.Error(t, err)
}

func TestVerifyWrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	token, _, _ := NewIssuer(priv, time.Hour).Issue("u", "d")

	otherPub, _, _ := ed25519.GenerateKey(nil)
	_, err := NewVerifier(otherPub).Verify(token)
	assert.Error(t, err)
}

func TestVerifyMalformed(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	_, err := NewVerifier(pub).Verify("a.b")
	assert.Error(t, err)
}
