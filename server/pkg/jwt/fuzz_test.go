package jwt_test

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/71g3pf4c3/binpass/server/pkg/jwt"
	"github.com/stretchr/testify/require"
)

// FuzzVerifyRejectsForgedTokens asserts the property the whole authentication
// layer rests on: only a token this key signed may verify. Tokens arrive from
// clients, so every other string must be refused rather than crash or, worse,
// authenticate someone.
func FuzzVerifyRejectsForgedTokens(f *testing.F) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(f, err)
	issuer := jwt.NewIssuer(priv, time.Hour)
	verifier := jwt.NewVerifier(pub)

	valid, _, err := issuer.Issue("user1", "device1")
	require.NoError(f, err)

	// A token signed by a different key must never be accepted.
	_, otherPriv, err := ed25519.GenerateKey(nil)
	require.NoError(f, err)
	foreign, _, err := jwt.NewIssuer(otherPriv, time.Hour).Issue("user1", "device1")
	require.NoError(f, err)

	for _, seed := range []string{
		valid,
		foreign,
		"",
		".",
		"..",
		"a.b.c",
		"eyJhbGciOiJub25lIn0..",
		valid + "x",
		valid[:len(valid)-1],
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, token string) {
		claims, err := verifier.Verify(token)
		if err != nil {
			return
		}
		// Anything that verified must be the token we issued: no other input
		// may produce claims.
		require.Equal(t, valid, token, "verified a token we did not issue")
		require.NotNil(t, claims)
		require.Equal(t, "user1", claims.Subject)
		require.Equal(t, "device1", claims.DeviceID)
	})
}
