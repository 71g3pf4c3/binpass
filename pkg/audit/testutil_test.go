package audit

import (
	"time"

	"github.com/71g3pf4c3/binpass/pkg/secret"
)

// testNow is a fixed reference time for deterministic expiry tests.
var testNow = time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)

// parseTestSecret is a test helper that creates a secret from a raw body
// string.
func parseTestSecret(body string) *secret.Secret {
	return secret.Parse([]byte(body))
}
