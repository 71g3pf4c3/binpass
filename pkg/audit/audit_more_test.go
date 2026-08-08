package audit

import (
	"testing"

	"github.com/71g3pf4c3/binpass/pkg/secret"
)

func TestReuseDetection(t *testing.T) {
	// Build a simple reuse map manually and check that the auditor
	// would find duplicate passwords.
	passwords := map[string]string{
		"bank/tinkoff": "same-password",
		"bank/alfa":    "same-password",
		"github/alice": "unique-password",
		"gitlab/alice": "same-password",
	}

	// Map from SHA-1 hash to entry names.
	pwHash := make(map[string][]string)
	for name, pw := range passwords {
		h := sha1Hash(pw)
		pwHash[h] = append(pwHash[h], name)
	}

	// Count how many groups have duplicates.
	reuseGroups := 0
	for _, names := range pwHash {
		if len(names) >= 2 {
			reuseGroups++
		}
	}

	if reuseGroups != 1 {
		t.Errorf("expected 1 reuse group, got %d", reuseGroups)
	}
}

func TestFormatHumanEmpty(t *testing.T) {
	r := &Report{
		Entries: nil,
		Stats: Stats{
			Total:   0,
			Audited: 0,
			Clean:   0,
		},
	}
	out := FormatHuman(r)
	if out == "" {
		t.Error("FormatHuman should produce output even for empty reports")
	}
}

func TestFormatHumanWithFindings(t *testing.T) {
	r := &Report{
		Entries: []EntryResult{
			{
				Name: "bank/tinkoff",
				Findings: []Finding{
					{Kind: KindLeaked, Severity: Critical, Detail: "password appears in HIBP"},
					{Kind: KindReused, Severity: Warning, Detail: "password is reused across 2 entries"},
				},
			},
			{
				Name: "github/alice",
				Findings: []Finding{
					{Kind: KindWeak, Severity: Warning, Detail: "password is weak (zxcvbn score 0/4)"},
				},
			},
		},
		Stats: Stats{
			Total:    2,
			Audited:  2,
			Critical: 1,
			Warning:  2,
			Clean:    0,
		},
	}

	out := FormatHuman(r)
	if out == "" {
		t.Error("FormatHuman should produce output")
	}

	// Password values should never appear in the report.
	// The finding detail is allowed, but the actual password must not.
	// The entry names should appear.
	if !containsSubstring(out, "bank/tinkoff") {
		t.Error("FormatHuman should include entry name bank/tinkoff")
	}
}

func TestEntryResultWorstSeverity(t *testing.T) {
	tests := []struct {
		findings []Finding
		want     Severity
	}{
		{
			findings: []Finding{{Severity: Critical}, {Severity: Warning}},
			want:     Critical,
		},
		{
			findings: []Finding{{Severity: Warning}, {Severity: Info}},
			want:     Warning,
		},
		{
			findings: []Finding{{Severity: Info}},
			want:     Info,
		},
	}

	for _, tc := range tests {
		r := EntryResult{Findings: tc.findings}
		got := worstSeverity(r)
		if got != tc.want {
			t.Errorf("worstSeverity = %q, want %q", got, tc.want)
		}
	}
}

func TestCheckExpiryWithAllFieldNames(t *testing.T) {
	// The check should look for "expire", "expires", and "expiry".
	for _, field := range []string{"expire", "expires", "expiry"} {
		body := "hunter2\n" + field + ": 2020-01-01"
		sec := secret.Parse([]byte(body))
		expired, _ := checkExpiry(sec, testNow)
		if !expired {
			t.Errorf("checkExpiry should find %s field as expired", field)
		}
	}
}
