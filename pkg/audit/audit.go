// Package audit checks a password store for weak, leaked, reused and expired
// passwords.
//
// Audit decrypts every entry in the store, which may require touching a hardware
// token for each one (§3.3 of ARCHITECTURE.md). The --parallel flag enables
// concurrent decryption, but it is not the default when a hardware token is
// detected, because hammering a token with concurrent touch requests is a bad
// user experience.
//
// Output is available in JSON (--format=json) for programmatic consumption and
// in a human-readable format grouped by severity. Passwords are never included
// in the output, only entry names and verdicts.
package audit

import (
	"context"
	"time"

	"github.com/71g3pf4c3/binpass/pkg/secret"
	"github.com/71g3pf4c3/binpass/pkg/store"
)

// Severity classifies audit findings.
type Severity string

const (
	// Critical means the password is known to be compromised (HIBP match) or
	// trivially guessable.
	Critical Severity = "critical"
	// Warning means the password is weak or reused across multiple entries.
	Warning Severity = "warning"
	// Info means the password is expired or near expiry.
	Info Severity = "info"
)

// Finding describes a single audit issue with one entry.
type Finding struct {
	// Kind is the category of the finding.
	Kind Kind
	// Severity is the severity level.
	Severity Severity
	// Detail is a human-readable explanation, suitable for display.
	Detail string
}

// Kind identifies the type of audit finding.
type Kind string

const (
	// KindLeaked means the password appears in the HIBP database.
	KindLeaked Kind = "leaked"
	// KindWeak means the password scores poorly on zxcvbn.
	KindWeak Kind = "weak"
	// KindReused means the same password appears in multiple entries.
	KindReused Kind = "reused"
	// KindExpired means the entry has passed its TTL.
	KindExpired Kind = "expired"
)

// EntryResult is the set of findings for a single store entry.
type EntryResult struct {
	// Name is the store path of the entry.
	Name string
	// Findings are the issues discovered.
	Findings []Finding
}

// Report is the complete audit output.
type Report struct {
	// Entries are the results, sorted by severity (critical first) then name.
	Entries []EntryResult
	// Skipped lists entries that could not be decrypted, with the error.
	Skipped []SkippedEntry
	// Stats holds summary counters.
	Stats Stats
}

// SkippedEntry records an entry that could not be audited.
type SkippedEntry struct {
	// Name is the store path.
	Name string
	// Error describes why the entry was skipped.
	Error string
}

// Stats holds summary counters for the audit.
type Stats struct {
	// Total is the number of entries in the store.
	Total int
	// Audited is the number of entries successfully decrypted and checked.
	Audited int
	// Critical is the number of entries with at least one critical finding.
	Critical int
	// Warning is the number of entries with at least one warning finding.
	Warning int
	// Info is the number of entries with at least one info finding.
	Info int
	// Clean is the number of entries with no findings.
	Clean int
}

// Options configures the audit.
type Options struct {
	// HIBP enables the Have I Been Pwned check. When false, the leaked check
	// is skipped entirely.
	HIBP bool
	// Strength enables the zxcvbn password strength check.
	Strength bool
	// Reuse enables the password reuse check.
	Reuse bool
	// Expired enables the expiry check. Entries are considered expired if they
	// carry an "expire:" or "expires:" field whose value is a date in the
	// past.
	Expired bool
	// Parallel is the number of concurrent decryption goroutines. 0 or 1 means
	// sequential.
	Parallel int
}

// DefaultOptions returns the default audit options: all checks enabled, single
// goroutine.
func DefaultOptions() Options {
	return Options{
		HIBP:     true,
		Strength: true,
		Reuse:    true,
		Expired:  true,
		Parallel: 1,
	}
}

// Auditor runs an audit against a store.
type Auditor struct {
	// Store is the password store to audit.
	Store *store.Store
	// Opts controls which checks are run.
	Opts Options
	// HIBPClient checks passwords against the HIBP database.
	HIBPClient HIBPChecker
	// Now is the current time, overridable for testing.
	Now func() time.Time
}

// Run executes the audit and returns a report.
func (a *Auditor) Run(ctx context.Context) (*Report, error) {
	if a.Now == nil {
		a.Now = time.Now
	}
	if a.HIBPClient == nil {
		a.HIBPClient = &noopHIBP{}
	}

	entries, err := a.Store.List("")
	if err != nil {
		return nil, err
	}

	report := &Report{Stats: Stats{Total: len(entries)}}

	// Decrypt all entries. When parallel > 1, use goroutines; otherwise
	// sequential to avoid hammering hardware tokens.
	type decrypted struct {
		name string
		sec  *secret.Secret
		err  error
	}

	var decryptedEntries []decrypted
	if a.Opts.Parallel <= 1 {
		for _, name := range entries {
			sec, err := a.Store.Get(name)
			decryptedEntries = append(decryptedEntries, decrypted{name: name, sec: sec, err: err})
		}
	} else {
		ch := make(chan decrypted, len(entries))
		sem := make(chan struct{}, a.Opts.Parallel)
		for _, name := range entries {
			sem <- struct{}{}
			go func(n string) {
				defer func() { <-sem }()
				sec, err := a.Store.Get(n)
				ch <- decrypted{name: n, sec: sec, err: err}
			}(name)
		}
		for range entries {
			decryptedEntries = append(decryptedEntries, <-ch)
		}
	}

	// Build password → names map for reuse detection.
	pwHash := make(map[string][]string) // SHA-1 hash → entry names
	for _, d := range decryptedEntries {
		if d.err != nil {
			report.Skipped = append(report.Skipped, SkippedEntry{
				Name:  d.name,
				Error: d.err.Error(),
			})
			continue
		}
		report.Stats.Audited++
		pw := d.sec.Password()

		var result EntryResult
		result.Name = d.name

		// HIBP check.
		if a.Opts.HIBP {
			leaked, err := a.HIBPClient.Check(ctx, pw)
			if err != nil {
				result.Findings = append(result.Findings, Finding{
					Kind:     KindLeaked,
					Severity: Warning, // Downgrade: we can't confirm, only warn.
					Detail:   "HIBP check failed: " + err.Error(),
				})
			} else if leaked {
				result.Findings = append(result.Findings, Finding{
					Kind:     KindLeaked,
					Severity: Critical,
					Detail:   "password appears in the Have I Been Pwned database",
				})
			}
		}

		// Strength check.
		if a.Opts.Strength {
			if score := passwordStrength(pw); score < 2 {
				result.Findings = append(result.Findings, Finding{
					Kind:     KindWeak,
					Severity: Warning,
					Detail:   "password is weak (zxcvbn score " + itoa(score) + "/4)",
				})
			}
		}

		// Expiry check.
		if a.Opts.Expired {
			if expired, when := checkExpiry(d.sec, a.Now()); expired {
				detail := "password has expired"
				if !when.IsZero() {
					detail = "password expired on " + when.Format("2006-01-02")
				}
				result.Findings = append(result.Findings, Finding{
					Kind:     KindExpired,
					Severity: Info,
					Detail:   detail,
				})
			}
		}

		// Collect password hash for reuse detection.
		if a.Opts.Reuse && pw != "" {
			h := sha1Hash(pw)
			pwHash[h] = append(pwHash[h], d.name)
		}

		if len(result.Findings) > 0 {
			report.Entries = append(report.Entries, result)
		}
	}

	// Reuse detection: find passwords used by multiple entries.
	if a.Opts.Reuse {
		for _, names := range pwHash {
			if len(names) < 2 {
				continue
			}
			for _, name := range names {
				// Add reuse finding to existing entry, or create one.
				found := false
				for i := range report.Entries {
					if report.Entries[i].Name == name {
						report.Entries[i].Findings = append(report.Entries[i].Findings, Finding{
							Kind:     KindReused,
							Severity: Warning,
							Detail:   "password is reused across " + itoa(len(names)) + " entries",
						})
						found = true
						break
					}
				}
				if !found {
					report.Entries = append(report.Entries, EntryResult{
						Name: name,
						Findings: []Finding{{
							Kind:     KindReused,
							Severity: Warning,
							Detail:   "password is reused across " + itoa(len(names)) + " entries",
						}},
					})
				}
			}
		}
	}

	// Compute stats. An entry contributes to the bucket of its worst
	// severity only, so the buckets are mutually exclusive and sum to
	// Audited.
	for i := range report.Entries {
		switch worstSeverity(report.Entries[i]) {
		case Critical:
			report.Stats.Critical++
		case Warning:
			report.Stats.Warning++
		case Info:
			report.Stats.Info++
		}
	}
	report.Stats.Clean = report.Stats.Audited - report.Stats.Critical - report.Stats.Warning - report.Stats.Info

	sortEntries(report.Entries)
	return report, nil
}
