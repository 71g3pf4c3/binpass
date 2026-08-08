package importer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/71g3pf4c3/binpass/pkg/crypto"
	"github.com/71g3pf4c3/binpass/pkg/secret"
	"github.com/71g3pf4c3/binpass/pkg/store"
)

// setupAgeStore creates a temporary age-encrypted store for import/export tests.
func setupAgeStore(t *testing.T) (*store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate age identity: %v", err)
	}
	rcp := crypto.Recipient(id.Recipient().String())
	os.WriteFile(filepath.Join(dir, ".age-recipients"), []byte(rcp.String()+"\n"), 0600)

	ageBackend := crypto.NewAge(dir, func() ([]age.Identity, error) {
		return []age.Identity{id}, nil
	})
	s, err := store.New(store.Options{
		Dir: dir, Backends: []crypto.Crypto{ageBackend}, Default: ageBackend,
	})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	return s, dir
}

func TestImportThenReadRoundTrip(t *testing.T) {
	s, _ := setupAgeStore(t)

	// Import entries from a Bitwarden CSV.
	csv := `folder,favorite,type,name,login_username,login_password,login_uri,login_totp,notes
Social,0,login,Twitter,@alice,hunter2,https://twitter.com,,my account
Finance,0,login,Bank,alice,correct-horse-battery-staple,https://bank.com,JBSWY3DPEHPK3PXP,savings`

	imp := &BitwardenImporter{}
	entries, err := ImportAll(imp, strings.NewReader(csv))
	if err != nil {
		t.Fatalf("ImportAll: %v", err)
	}

	// Write to store.
	written, errs := WriteEntries(s, entries, false)
	if len(errs) > 0 {
		t.Fatalf("WriteEntries errors: %v", errs)
	}
	if len(written) != 2 {
		t.Fatalf("wrote %d entries, want 2", len(written))
	}

	// Read back and verify.
	sec, err := s.Get("Social/Twitter")
	if err != nil {
		t.Fatalf("Get Twitter: %v", err)
	}
	if sec.Password() != "hunter2" {
		t.Errorf("Twitter password = %q, want %q", sec.Password(), "hunter2")
	}
	u, _ := sec.Field("username")
	if u != "@alice" {
		t.Errorf("Twitter username = %q, want %q", u, "@alice")
	}

	sec2, err := s.Get("Finance/Bank")
	if err != nil {
		t.Fatalf("Get Bank: %v", err)
	}
	if sec2.Password() != "correct-horse-battery-staple" {
		t.Errorf("Bank password = %q, want %q", sec2.Password(), "correct-horse-battery-staple")
	}
	otp, ok := sec2.OTP()
	if !ok {
		t.Error("Bank should have an OTP URI")
	}
	if !strings.Contains(otp, "otpauth://") {
		t.Errorf("OTP = %q, should contain otpauth://", otp)
	}
}

func TestImportDryRun(t *testing.T) {
	s, _ := setupAgeStore(t)

	csv := `folder,favorite,type,name,login_username,login_password,login_uri
Social,0,login,Twitter,@alice,hunter2,https://twitter.com`

	imp := &BitwardenImporter{}
	entries, _ := ImportAll(imp, strings.NewReader(csv))

	plans := Plan(s, entries)
	if len(plans) != 1 {
		t.Fatalf("Plan returned %d entries, want 1", len(plans))
	}
	if plans[0].StorePath != "Social/Twitter" {
		t.Errorf("StorePath = %q, want %q", plans[0].StorePath, "Social/Twitter")
	}
	if !plans[0].HasPassword {
		t.Error("HasPassword should be true")
	}
	if plans[0].Conflict {
		t.Error("Conflict should be false for new entry")
	}

	// Write the entry, then check that dry-run detects the conflict.
	WriteEntries(s, entries, false)
	plans2 := Plan(s, entries)
	if len(plans2) != 1 {
		t.Fatalf("Plan returned %d entries, want 1", len(plans2))
	}
	if !plans2[0].Conflict {
		t.Error("Conflict should be true when entry already exists")
	}
}

func TestImportForceOverwrite(t *testing.T) {
	s, _ := setupAgeStore(t)

	// Write an entry first.
	s.Set("Social/Twitter", secret.New("old-password", ""))

	// Import the same entry with different password.
	csv := `folder,favorite,type,name,login_username,login_password,login_uri
Social,0,login,Twitter,@alice,new-password,https://twitter.com`
	imp := &BitwardenImporter{}
	entries, _ := ImportAll(imp, strings.NewReader(csv))

	// Without force: should skip.
	_, errs := WriteEntries(s, entries, false)
	if len(errs) == 0 {
		t.Error("expected error when overwriting without --force")
	}

	// With force: should overwrite.
	written, errs := WriteEntries(s, entries, true)
	if len(errs) > 0 {
		t.Errorf("unexpected errors with --force: %v", errs)
	}
	if len(written) != 1 {
		t.Fatalf("wrote %d entries, want 1", len(written))
	}

	sec, _ := s.Get("Social/Twitter")
	if sec.Password() != "new-password" {
		t.Errorf("password = %q, want %q", sec.Password(), "new-password")
	}
}

func TestImportPathTraversal(t *testing.T) {
	s, _ := setupAgeStore(t)

	// After normalisation, "../etc/passwd" becomes "etc/passwd" which is
	// valid. The path traversal is sanitised away by NormalizePath.
	// Direct path traversal is only possible if the caller sets e.Path
	// directly, bypassing normalisation.
	entries := []*Entry{
		{Title: "../etc/passwd", Password: "evil"},
		{Path: "../etc/shadow", Password: "evil2"},
	}

	written, errs := WriteEntries(s, entries, false)
	// Title-based entry: normalised to "etc/passwd", valid path.
	// Path-based entry: "../etc/shadow" is rejected by ValidatePath.
	if len(written) != 1 {
		t.Errorf("expected 1 written (normalised), got %d", len(written))
	}
	if len(errs) != 1 {
		t.Errorf("expected 1 error (path traversal), got %d", len(errs))
	}
}

func TestImportEmptyPassword(t *testing.T) {
	s, _ := setupAgeStore(t)

	csv := `folder,favorite,type,name,login_username,login_password,login_uri
Social,0,login,Twitter,@alice,,https://twitter.com`
	imp := &BitwardenImporter{}
	entries, _ := ImportAll(imp, strings.NewReader(csv))

	written, errs := WriteEntries(s, entries, false)
	if len(errs) > 0 {
		t.Errorf("unexpected errors: %v", errs)
	}
	if len(written) != 1 {
		t.Fatalf("wrote %d entries, want 1", len(written))
	}

	sec, _ := s.Get("Social/Twitter")
	if sec.Password() != "" {
		t.Errorf("expected empty password, got %q", sec.Password())
	}
}
