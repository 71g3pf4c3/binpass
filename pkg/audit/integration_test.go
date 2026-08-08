package audit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/71g3pf4c3/binpass/pkg/crypto"
	"github.com/71g3pf4c3/binpass/pkg/secret"
	"github.com/71g3pf4c3/binpass/pkg/store"
)

func TestAuditFullRun(t *testing.T) {
	dir := t.TempDir()

	// Generate age key pair for the test store.
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate age identity: %v", err)
	}
	rcp := crypto.Recipient(id.Recipient().String())

	// Write .age-recipients so the store can encrypt.
	if err := os.WriteFile(filepath.Join(dir, ".age-recipients"), []byte(rcp.String()+"\n"), 0600); err != nil {
		t.Fatalf("write recipients: %v", err)
	}

	ageBackend := crypto.NewAge(dir, func() ([]age.Identity, error) {
		return []age.Identity{id}, nil
	})
	s, err := store.New(store.Options{
		Dir:      dir,
		Backends: []crypto.Crypto{ageBackend},
		Default:  ageBackend,
	})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	// Write test entries.
	entries := []struct {
		name string
		sec  *secret.Secret
	}{
		{"weak", secret.New("password", "")},                        // weak by zxcvbn
		{"strong", secret.New("Kk7N9!mP2xLqR5vW", "")},              // strong by zxcvbn
		{"reused1", secret.New("same-password-123", "")},            // reused
		{"reused2", secret.New("same-password-123", "")},            // reused (same)
		{"expired", secret.New("hunter2", "expires: 2020-01-01\n")}, // expired
	}

	for _, e := range entries {
		if err := s.Set(e.name, e.sec); err != nil {
			t.Fatalf("set %s: %v", e.name, err)
		}
	}

	// Run audit with HIBP disabled (no network in test environment).
	auditor := &Auditor{
		Store: s,
		Opts: Options{
			HIBP:     false,
			Strength: true,
			Reuse:    true,
			Expired:  true,
			Parallel: 1,
		},
		HIBPClient: &noopHIBP{},
		Now:        func() time.Time { return time.Date(2024, 6, 15, 0, 0, 0, 0, time.UTC) },
	}

	report, err := auditor.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Verify we audited all entries.
	if report.Stats.Audited != 5 {
		t.Errorf("Audited = %d, want 5", report.Stats.Audited)
	}

	// "weak" should have a weak finding.
	if !hasFinding(report, "weak", KindWeak) {
		t.Error("expected weak finding for 'weak' entry")
	}

	// "reused1" and "reused2" should have reuse findings.
	if !hasFinding(report, "reused1", KindReused) {
		t.Error("expected reuse finding for 'reused1' entry")
	}
	if !hasFinding(report, "reused2", KindReused) {
		t.Error("expected reuse finding for 'reused2' entry")
	}

	// "expired" should have an expired finding.
	if !hasFinding(report, "expired", KindExpired) {
		t.Error("expected expired finding for 'expired' entry")
	}

	// "strong" should be clean (no findings).
	if hasAnyFinding(report, "strong") {
		t.Error("expected no findings for 'strong' entry")
	}

	// Stats must be internally consistent: Critical + Warning + Info + Clean = Audited.
	total := report.Stats.Critical + report.Stats.Warning + report.Stats.Info + report.Stats.Clean
	if total != report.Stats.Audited {
		t.Errorf("stats inconsistent: %d+%d+%d+%d = %d, want %d",
			report.Stats.Critical, report.Stats.Warning, report.Stats.Info, report.Stats.Clean,
			total, report.Stats.Audited)
	}

	// JSON output must not contain any "password" or "secret" field that echoes
	// the plaintext. The EntryResult struct deliberately omits such fields.
	reportJSON, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	reportStr := string(reportJSON)
	for _, forbidden := range []string{`"password"`, `"secret"`, `"plaintext"`} {
		if containsSubstring(reportStr, forbidden) {
			t.Errorf("JSON report contains forbidden field %q", forbidden)
		}
	}

	// Human-readable output must not contain a dedicated line that prints
	// the plaintext password. Entry names and finding text are acceptable.
	human := FormatHuman(report)
	for _, forbidden := range []string{`password:`, `secret:`} {
		if containsSubstring(human, forbidden) {
			t.Errorf("human report contains forbidden prefix %q", forbidden)
		}
	}
}

func TestAuditEmptyStore(t *testing.T) {
	dir := t.TempDir()
	id, _ := age.GenerateX25519Identity()
	rcp := crypto.Recipient(id.Recipient().String())
	os.WriteFile(filepath.Join(dir, ".age-recipients"), []byte(rcp.String()+"\n"), 0600)

	ageBackend := crypto.NewAge(dir, func() ([]age.Identity, error) {
		return []age.Identity{id}, nil
	})
	s, _ := store.New(store.Options{
		Dir: dir, Backends: []crypto.Crypto{ageBackend}, Default: ageBackend,
	})

	auditor := &Auditor{Store: s, Opts: DefaultOptions(), HIBPClient: &noopHIBP{}}
	report, err := auditor.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Stats.Total != 0 {
		t.Errorf("Total = %d, want 0", report.Stats.Total)
	}
	if report.Stats.Audited != 0 {
		t.Errorf("Audited = %d, want 0", report.Stats.Audited)
	}
}

func TestAuditParallelDecryption(t *testing.T) {
	dir := t.TempDir()
	id, _ := age.GenerateX25519Identity()
	rcp := crypto.Recipient(id.Recipient().String())
	os.WriteFile(filepath.Join(dir, ".age-recipients"), []byte(rcp.String()+"\n"), 0600)

	ageBackend := crypto.NewAge(dir, func() ([]age.Identity, error) {
		return []age.Identity{id}, nil
	})
	s, _ := store.New(store.Options{
		Dir: dir, Backends: []crypto.Crypto{ageBackend}, Default: ageBackend,
	})

	// Write multiple entries.
	for i := 0; i < 10; i++ {
		s.Set("entry/"+itoa(i), secret.New("password-"+itoa(i), ""))
	}

	auditor := &Auditor{
		Store:      s,
		Opts:       Options{HIBP: false, Strength: true, Reuse: false, Expired: false, Parallel: 4},
		HIBPClient: &noopHIBP{},
	}
	report, err := auditor.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Stats.Audited != 10 {
		t.Errorf("Audited = %d, want 10", report.Stats.Audited)
	}
}

func TestAuditWithHIBPStub(t *testing.T) {
	dir := t.TempDir()

	// Generate age key pair for the test store.
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate age identity: %v", err)
	}
	rcp := crypto.Recipient(id.Recipient().String())

	// Write .age-recipients so the store can encrypt.
	if err := os.WriteFile(filepath.Join(dir, ".age-recipients"), []byte(rcp.String()+"\n"), 0600); err != nil {
		t.Fatalf("write recipients: %v", err)
	}

	ageBackend := crypto.NewAge(dir, func() ([]age.Identity, error) {
		return []age.Identity{id}, nil
	})
	s, err := store.New(store.Options{
		Dir:      dir,
		Backends: []crypto.Crypto{ageBackend},
		Default:  ageBackend,
	})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	// Write test entries: "leaked" with a known HIBP password, "safe" with a
	// random strong password unlikely to be in HIBP.
	if err := s.Set("leaked", secret.New("password", "")); err != nil {
		t.Fatalf("set leaked: %v", err)
	}
	if err := s.Set("safe", secret.New("Kk7N9!mP2xLqR5vW8zT3xM", "")); err != nil {
		t.Fatalf("set safe: %v", err)
	}

	// Stub the HIBP k-anonymity API.
	// SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
	// Prefix 5BAA6 -> suffix 1E4C9B93F3F0682250B6CF8331B7EE68FD8 (present).
	// Any other prefix -> non-matching suffix or empty list.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prefix := strings.TrimPrefix(r.URL.Path, "/range/")
		switch prefix {
		case "5BAA6":
			w.Write([]byte("1E4C9B93F3F0682250B6CF8331B7EE68FD8:12345\n"))
			w.Write([]byte("0000000000000000000000000000000000NOISE:3\n"))
		default:
			w.Write([]byte(""))
		}
	}))
	defer srv.Close()

	auditor := &Auditor{
		Store: s,
		Opts: Options{
			HIBP:     true,
			Strength: false,
			Reuse:    false,
			Expired:  false,
			Parallel: 1,
		},
		HIBPClient: &HIBPClient{
			Endpoint: srv.URL + "/range/",
			Client:   srv.Client(),
			cache:    make(map[string]map[string]int),
		},
	}

	report, err := auditor.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// "leaked" must have a KindLeaked finding at Critical severity.
	if !hasFinding(report, "leaked", KindLeaked) {
		t.Error("expected leaked finding for 'leaked' entry")
	}
	for _, e := range report.Entries {
		if e.Name != "leaked" {
			continue
		}
		for _, f := range e.Findings {
			if f.Kind == KindLeaked && f.Severity != Critical {
				t.Errorf("leaked finding severity = %s, want %s", f.Severity, Critical)
			}
		}
	}

	// "safe" must have no findings.
	if hasAnyFinding(report, "safe") {
		t.Error("expected no findings for 'safe' entry")
	}

	// Stats: both audited, one critical, one clean.
	if report.Stats.Audited != 2 {
		t.Errorf("Audited = %d, want 2", report.Stats.Audited)
	}
	if report.Stats.Critical != 1 {
		t.Errorf("Critical = %d, want 1", report.Stats.Critical)
	}
	if report.Stats.Clean != 1 {
		t.Errorf("Clean = %d, want 1", report.Stats.Clean)
	}
}
