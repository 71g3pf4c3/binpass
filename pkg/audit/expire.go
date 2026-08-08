package audit

import (
	"strings"
	"time"

	"github.com/71g3pf4c3/binpass/pkg/secret"
)

// checkExpiry looks for "expire:" or "expires:" fields in the secret and
// reports whether the entry is past its expiry date. Returns the expiry
// time if set, zero value otherwise.
func checkExpiry(sec *secret.Secret, now time.Time) (bool, time.Time) {
	for _, fieldName := range []string{"expire", "expires", "expiry"} {
		val, ok := sec.Field(fieldName)
		if !ok || val == "" {
			continue
		}

		when, err := parseExpiry(val, now)
		if err != nil {
			continue
		}
		if when.Before(now) {
			return true, when
		}
	}
	return false, time.Time{}
}

// parseExpiry interprets an expiry value. Supports RFC 3339 dates, simple
// date formats (2006-01-02), and relative durations (e.g. "90d").
func parseExpiry(val string, now time.Time) (time.Time, error) {
	// Try RFC 3339 full timestamp.
	if t, err := time.Parse(time.RFC3339, val); err == nil {
		return t, nil
	}

	// Try date-only format.
	if t, err := time.Parse("2006-01-02", val); err == nil {
		return t, nil
	}

	// Try European date format.
	if t, err := time.Parse("02.01.2006", val); err == nil {
		return t, nil
	}

	// Try relative duration: "90d", "1y", etc.
	if strings.HasSuffix(val, "d") {
		return parseRelativeDuration(val, now)
	}

	return time.Time{}, errUnparseableExpiry
}

var errUnparseableExpiry = &expiryParseError{}

type expiryParseError struct{}

func (expiryParseError) Error() string { return "expiry: unparseable value" }

// parseRelativeDuration handles "Nd" (N days from now) style durations.
func parseRelativeDuration(val string, now time.Time) (time.Time, error) {
	numStr := strings.TrimSuffix(val, "d")
	var days int
	for _, ch := range numStr {
		if ch < '0' || ch > '9' {
			return time.Time{}, errUnparseableExpiry
		}
		days = days*10 + int(ch-'0')
	}
	return now.AddDate(0, 0, days), nil
}
