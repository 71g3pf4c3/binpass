package audit

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/71g3pf4c3/binpass/pkg/crypto"
	"github.com/71g3pf4c3/binpass/pkg/secret"
	"github.com/71g3pf4c3/binpass/pkg/store"
)

// --- parseExpiry (expire.go:33) ---

func TestParseExpiry(t *testing.T) {
	now := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)

	// RFC3339
	if _, err := parseExpiry("2020-01-01T00:00:00Z", now); err != nil {
		t.Errorf("RFC3339 should parse: %v", err)
	}

	// Date only
	if _, err := parseExpiry("2020-01-01", now); err != nil {
		t.Errorf("date-only should parse: %v", err)
	}

	// European
	if _, err := parseExpiry("01.01.2020", now); err != nil {
		t.Errorf("European should parse: %v", err)
	}

	// Relative duration "90d"
	when, err := parseExpiry("90d", now)
	if err != nil {
		t.Fatalf("relative 90d: %v", err)
	}
	expected := now.AddDate(0, 0, 90)
	if !when.Equal(expected) {
		t.Errorf("90d: got %v, want %v", when, expected)
	}

	// Unparseable
	_, err = parseExpiry("not-a-date", now)
	if err == nil {
		t.Error("should fail for unparseable value")
	}

	// Non-d suffix (like "1y") should fail
	_, err = parseExpiry("1y", now)
	if err == nil {
		t.Error("should fail for '1y' suffix")
	}
}

// --- expiryParseError.Error (expire.go:61) ---

func TestExpiryParseError(t *testing.T) {
	err := errUnparseableExpiry
	if err.Error() != "expiry: unparseable value" {
		t.Errorf("Error() = %q, want %q", err.Error(), "expiry: unparseable value")
	}
}

// --- parseRelativeDuration (expire.go:64) ---

func TestParseRelativeDuration(t *testing.T) {
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	// Valid: "30d"
	when, err := parseRelativeDuration("30d", now)
	if err != nil {
		t.Fatalf("30d: %v", err)
	}
	if !when.Equal(now.AddDate(0, 0, 30)) {
		t.Errorf("30d: got %v, want %v", when, now.AddDate(0, 0, 30))
	}

	// Zero days
	when, err = parseRelativeDuration("0d", now)
	if err != nil {
		t.Fatalf("0d: %v", err)
	}
	if !when.Equal(now) {
		t.Errorf("0d: got %v, want %v", when, now)
	}

	// Invalid: non-numeric "abcd"
	_, err = parseRelativeDuration("abcd", now)
	if err == nil {
		t.Error("should fail for non-numeric")
	}

	// Large number
	when, err = parseRelativeDuration("365d", now)
	if err != nil {
		t.Fatalf("365d: %v", err)
	}
	if !when.Equal(now.AddDate(0, 0, 365)) {
		t.Errorf("365d: got %v, want %v", when, now.AddDate(0, 0, 365))
	}
}

// --- NewHIBPClient (hibp.go:38) ---

func TestNewHIBPClient(t *testing.T) {
	client := NewHIBPClient()
	if client == nil {
		t.Fatal("NewHIBPClient returned nil")
	}
	if client.Endpoint != "https://api.pwnedpasswords.com/range/" {
		t.Errorf("Endpoint = %q, want default HIBP URL", client.Endpoint)
	}
	if client.Client == nil {
		t.Error("Client should not be nil")
	}
	if client.cache == nil {
		t.Error("cache should be initialized")
	}
}

// --- fetchRange error paths (hibp.go:75) ---

func TestHIBPClientFetchRangeError(t *testing.T) {
	// Server returns 500
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := &HIBPClient{
		Endpoint: server.URL + "/range/",
		Client:   server.Client(),
		cache:    make(map[string]map[string]int),
	}

	_, err := client.Check(context.Background(), "password")
	if err == nil {
		t.Error("expected error for 500 response")
	}
}

func TestHIBPClientFetchRangeEmptyEndpoint(t *testing.T) {
	// When Endpoint is empty, it should use the default HIBP URL.
	// Test that the code path works (it will hit the real API or fail with network error).
	client := &HIBPClient{
		Endpoint: "",                                         // triggers default URL path
		Client:   &http.Client{Timeout: 1 * time.Nanosecond}, // will fail quickly
		cache:    make(map[string]map[string]int),
	}
	_, err := client.Check(context.Background(), "test")
	// Should get a network timeout error, not a nil URL.
	if err == nil {
		t.Error("expected error for empty endpoint with short timeout")
	}
}

// --- sha1Prefix/Suffix edge cases (report.go:20,29) ---

func TestSHA1PrefixShort(t *testing.T) {
	// hash shorter than 5 chars
	if sha1Prefix("AB") != "AB" {
		t.Errorf("short prefix: got %q", sha1Prefix("AB"))
	}
}

func TestSHA1SuffixShort(t *testing.T) {
	if sha1Suffix("AB") != "" {
		t.Errorf("short suffix: got %q", sha1Suffix("AB"))
	}
	if sha1Suffix("ABCDE") != "" {
		t.Errorf("5-char suffix: got %q", sha1Suffix("ABCDE"))
	}
}

// --- itoa multi-digit (report.go:37) ---

func TestItoa(t *testing.T) {
	tests := []struct {
		in   int
		want string
	}{
		{0, "0"}, {1, "1"}, {9, "9"}, {10, "10"}, {42, "42"}, {100, "100"}, {999, "999"},
	}
	for _, tc := range tests {
		got := itoa(tc.in)
		if got != tc.want {
			t.Errorf("itoa(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// --- worstSeverity no findings (report.go:58) ---

func TestWorstSeverityNoFindings(t *testing.T) {
	r := EntryResult{Name: "clean", Findings: nil}
	if got := worstSeverity(r); got != Info {
		t.Errorf("worstSeverity with no findings = %q, want Info", got)
	}
}

// --- sortEntries comprehensive (report.go:45) ---

func TestSortEntries(t *testing.T) {
	entries := []EntryResult{
		{Name: "z-warn", Findings: []Finding{{Severity: Warning}}},
		{Name: "a-crit", Findings: []Finding{{Severity: Critical}}},
		{Name: "m-info", Findings: []Finding{{Severity: Info}}},
		{Name: "b-crit", Findings: []Finding{{Severity: Critical}}},
	}
	sortEntries(entries)
	// Critical first, then alphabetical within severity.
	if entries[0].Name != "a-crit" {
		t.Errorf("entries[0] = %q", entries[0].Name)
	}
	if entries[1].Name != "b-crit" {
		t.Errorf("entries[1] = %q", entries[1].Name)
	}
	if entries[2].Name != "z-warn" {
		t.Errorf("entries[2] = %q", entries[2].Name)
	}
	if entries[3].Name != "m-info" {
		t.Errorf("entries[3] = %q", entries[3].Name)
	}
}

// --- FormatHuman with Skipped (report.go:71) ---

func TestFormatHumanWithSkipped(t *testing.T) {
	r := &Report{
		Skipped: []SkippedEntry{{Name: "unreadable", Error: "decryption failed"}},
		Stats:   Stats{Total: 1, Audited: 0},
	}
	out := FormatHuman(r)
	if !containsSubstring(out, "Skipped") {
		t.Error("should mention skipped entries")
	}
	// FormatHuman renders a summary count line for skipped entries, not the
	// per-entry error detail.
	if !containsSubstring(out, "could not be decrypted") {
		t.Error("should mention skipped entries count")
	}
}

// --- Auditor.Run with HIBP error (audit.go:207-213) ---

type errorHIBP struct{}

func (errorHIBP) Check(_ context.Context, _ string) (bool, error) {
	return false, fmt.Errorf("HIBP API is down")
}

func TestAuditHIBPErrorDowngrade(t *testing.T) {
	dir := t.TempDir()
	id, _ := age.GenerateX25519Identity()
	rcp := crypto.Recipient(id.Recipient().String())
	_ = os.WriteFile(filepath.Join(dir, ".age-recipients"), []byte(rcp.String()+"\n"), 0600)
	ageBackend := crypto.NewAge(dir, func() ([]age.Identity, error) { return []age.Identity{id}, nil })
	s, _ := store.New(store.Options{Dir: dir, Backends: []crypto.Crypto{ageBackend}, Default: ageBackend})
	_ = s.Set("test", secret.New("password", ""))

	auditor := &Auditor{
		Store:      s,
		Opts:       Options{HIBP: true, Strength: false, Reuse: false, Expired: false, Parallel: 1},
		HIBPClient: &errorHIBP{},
	}
	report, err := auditor.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(report.Entries) != 1 {
		t.Fatalf("entries: %d", len(report.Entries))
	}
	found := false
	for _, f := range report.Entries[0].Findings {
		if f.Kind == KindLeaked && f.Severity == Warning {
			found = true
		}
	}
	if !found {
		t.Error("expected HIBP error downgraded to Warning")
	}
}

// --- Auditor.Run with parallel > 1 AND decryption error ---

func TestAuditParallelWithDecryptionError(t *testing.T) {
	dir := t.TempDir()
	id, _ := age.GenerateX25519Identity()
	rcp := crypto.Recipient(id.Recipient().String())
	_ = os.WriteFile(filepath.Join(dir, ".age-recipients"), []byte(rcp.String()+"\n"), 0600)
	ageBackend := crypto.NewAge(dir, func() ([]age.Identity, error) { return []age.Identity{id}, nil })
	s, _ := store.New(store.Options{Dir: dir, Backends: []crypto.Crypto{ageBackend}, Default: ageBackend})
	_ = s.Set("a", secret.New("pw1", ""))
	_ = s.Set("b", secret.New("pw2", ""))

	// Remove the identity so decryption fails.
	// Actually, the identity resolver is a closure that returns the key.
	// We need to create a new store with a resolver that returns empty identities.
	ageBackend2 := crypto.NewAge(dir, func() ([]age.Identity, error) { return nil, nil })
	s2, _ := store.New(store.Options{Dir: dir, Backends: []crypto.Crypto{ageBackend2}, Default: ageBackend2})

	auditor := &Auditor{
		Store:      s2,
		Opts:       Options{HIBP: false, Strength: true, Reuse: false, Expired: false, Parallel: 4},
		HIBPClient: &noopHIBP{},
	}
	report, err := auditor.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(report.Skipped) != 2 {
		t.Errorf("expected 2 skipped, got %d", len(report.Skipped))
	}
	if report.Stats.Audited != 0 {
		t.Errorf("Audited = %d, want 0", report.Stats.Audited)
	}
}
