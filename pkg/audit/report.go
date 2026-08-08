package audit

import (
	"crypto/sha1" //nolint:gosec // HIBP uses SHA-1 by design.
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// sha1Hash computes the uppercase hex SHA-1 hash of a password. SHA-1 is used
// by the HIBP k-anonymity protocol; this is not a security decision.
func sha1Hash(password string) string {
	h := sha1.Sum([]byte(password)) //nolint:gosec // HIBP protocol mandates SHA-1.
	return strings.ToUpper(hex.EncodeToString(h[:]))
}

// sha1Prefix returns the first 5 characters of the SHA-1 hash, which is what
// the HIBP k-anonymity protocol sends to the API.
func sha1Prefix(hash string) string {
	if len(hash) < 5 {
		return hash
	}
	return hash[:5]
}

// sha1Suffix returns the part of the SHA-1 hash after the 5-character prefix,
// which is what the HIBP API returns for local comparison.
func sha1Suffix(hash string) string {
	if len(hash) <= 5 {
		return ""
	}
	return hash[5:]
}

// itoa converts a non-negative integer to its decimal string.
func itoa(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return itoa(n/10) + string(rune('0'+n%10))
}

// sortEntries sorts audit results by severity (critical first), then by name.
func sortEntries(entries []EntryResult) {
	severityOrder := map[Severity]int{Critical: 0, Warning: 1, Info: 2}
	sort.Slice(entries, func(i, j int) bool {
		si, sj := worstSeverity(entries[i]), worstSeverity(entries[j])
		oi, oj := severityOrder[si], severityOrder[sj]
		if oi != oj {
			return oi < oj
		}
		return entries[i].Name < entries[j].Name
	})
}

// worstSeverity returns the most severe finding's severity.
func worstSeverity(r EntryResult) Severity {
	for _, s := range []Severity{Critical, Warning, Info} {
		for _, f := range r.Findings {
			if f.Severity == s {
				return s
			}
		}
	}
	return Info
}

// FormatHuman produces a human-readable audit report grouped by severity.
// Passwords are never included.
func FormatHuman(r *Report) string {
	var sb strings.Builder

	critical := filterBySeverity(r.Entries, Critical)
	warnings := filterBySeverity(r.Entries, Warning)
	info := filterBySeverity(r.Entries, Info)

	if len(critical) > 0 {
		sb.WriteString("CRITICAL — leaked or trivially guessable passwords:\n")
		for _, e := range critical {
			sb.WriteString(fmt.Sprintf("  %s\n", e.Name))
			for _, f := range e.Findings {
				if f.Severity == Critical {
					sb.WriteString(fmt.Sprintf("    - %s\n", f.Detail))
				}
			}
		}
		sb.WriteString("\n")
	}

	if len(warnings) > 0 {
		sb.WriteString("WARNING — weak or reused passwords:\n")
		for _, e := range warnings {
			sb.WriteString(fmt.Sprintf("  %s\n", e.Name))
			for _, f := range e.Findings {
				if f.Severity == Warning {
					sb.WriteString(fmt.Sprintf("    - %s\n", f.Detail))
				}
			}
		}
		sb.WriteString("\n")
	}

	if len(info) > 0 {
		sb.WriteString("INFO — expired passwords:\n")
		for _, e := range info {
			sb.WriteString(fmt.Sprintf("  %s\n", e.Name))
			for _, f := range e.Findings {
				if f.Severity == Info {
					sb.WriteString(fmt.Sprintf("    - %s\n", f.Detail))
				}
			}
		}
		sb.WriteString("\n")
	}

	sb.WriteString(fmt.Sprintf("Total: %d | Audited: %d | Critical: %d | Warning: %d | Info: %d | Clean: %d\n",
		r.Stats.Total, r.Stats.Audited, r.Stats.Critical, r.Stats.Warning, r.Stats.Info, r.Stats.Clean))

	if len(r.Skipped) > 0 {
		sb.WriteString(fmt.Sprintf("\nSkipped: %d entries could not be decrypted\n", len(r.Skipped)))
	}

	return sb.String()
}

// filterBySeverity returns entries that have at least one finding with the
// given severity.
func filterBySeverity(entries []EntryResult, s Severity) []EntryResult {
	var out []EntryResult
	for _, e := range entries {
		for _, f := range e.Findings {
			if f.Severity == s {
				out = append(out, e)
				break
			}
		}
	}
	return out
}
