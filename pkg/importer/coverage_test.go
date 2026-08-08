package importer

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"iter"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tobischo/gokeepasslib/v3"
)

// ---------------------------------------------------------------------------
// WriteEntries: store.Set error path (export.go:100)
// ---------------------------------------------------------------------------

func TestWriteEntriesSetError(t *testing.T) {
	s, dir := setupAgeStore(t)
	// Corrupt the recipients file so that encryption fails on Set. readRecipientsFile
	// only collects lines without validating them, so the failure surfaces at
	// Encrypt time via ParseAgeRecipients.
	if err := os.WriteFile(filepath.Join(dir, ".age-recipients"), []byte("age1invalidrecipient\n"), 0600); err != nil {
		t.Fatalf("corrupt recipients: %v", err)
	}
	entries := []*Entry{{Title: "test", Password: "pw"}}
	written, errs := WriteEntries(s, entries, false)
	if len(written) > 0 {
		t.Errorf("expected no writes, got %d", len(written))
	}
	if len(errs) == 0 {
		t.Error("expected error from Set")
	}
}

// ---------------------------------------------------------------------------
// WriteEntries: attachment happy path (export.go:106-119)
// ---------------------------------------------------------------------------

func TestWriteEntriesWithAttachment(t *testing.T) {
	s, _ := setupAgeStore(t)
	entries := []*Entry{
		{
			Title:    "doc",
			Password: "secret",
			Attachments: []Attachment{
				{Name: "file.txt", Data: []byte("hello world")},
			},
		},
	}
	written, errs := WriteEntries(s, entries, false)
	if len(errs) > 0 {
		t.Fatalf("errors: %v", errs)
	}
	// Should write 2 entries: the main entry + the attachment.
	if len(written) != 2 {
		t.Fatalf("wrote %d, want 2", len(written))
	}
	// Verify attachment exists and is base64.
	sec, err := s.Get("doc/file.txt.b64")
	if err != nil {
		t.Fatalf("Get attachment: %v", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(sec.Password())
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	if string(decoded) != "hello world" {
		t.Errorf("attachment content = %q, want %q", string(decoded), "hello world")
	}
}

// ---------------------------------------------------------------------------
// WriteEntries: attachment element with invalid base path (export.go:82)
// ---------------------------------------------------------------------------

func TestWriteEntriesAttachmentError(t *testing.T) {
	s, _ := setupAgeStore(t)
	entries := []*Entry{
		{
			Path:     "../traversal", // invalid, will fail StorePath
			Password: "pw",
			Attachments: []Attachment{
				{Name: "a.txt", Data: []byte("data")},
			},
		},
	}
	written, errs := WriteEntries(s, entries, false)
	if len(written) != 0 {
		t.Errorf("expected 0 writes, got %d", len(written))
	}
	if len(errs) == 0 {
		t.Error("expected errors for invalid path")
	}
}

// ---------------------------------------------------------------------------
// ImportAll: entry-level error keeps partial entry (importer.go:108-116)
// ---------------------------------------------------------------------------

type errorImporter struct{}

var _ Importer = errorImporter{}

func (errorImporter) Name() string            { return "error" }
func (errorImporter) Detect(_ io.Reader) bool { return false }
func (errorImporter) Import(_ io.Reader) iter.Seq2[*Entry, error] {
	return func(yield func(*Entry, error) bool) {
		// Yield a partial entry with an error.
		if !yield(&Entry{Title: "partial"}, fmt.Errorf("partial error")) {
			return
		}
	}
}

func TestImportAllWithEntryError(t *testing.T) {
	imp := &errorImporter{}
	entries, err := ImportAll(imp, strings.NewReader(""))
	if len(entries) != 1 {
		t.Fatalf("expected 1 partial entry, got %d", len(entries))
	}
	if entries[0].Title != "partial" {
		t.Errorf("Title = %q, want %q", entries[0].Title, "partial")
	}
	if err == nil {
		t.Error("expected error from ImportAll")
	}
}

// ---------------------------------------------------------------------------
// ImportAll: iteration stopped path (importers' `if !yield(...) { return }`)
// ---------------------------------------------------------------------------

func TestImportIterationStopped(t *testing.T) {
	imp := &BitwardenImporter{}
	src := "folder,name,password\nSocial,A,pw\nSocial,B,pw2"
	count := 0
	for e, err := range imp.Import(strings.NewReader(src)) {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		_ = e
		count++
		// Break out after the first entry: importers must return cleanly when
		// the caller stops iterating.
		break
	}
	if count != 1 {
		t.Fatalf("iterated %d entries, want 1", count)
	}
}

// ---------------------------------------------------------------------------
// ToSecret: all structured fields + notes newline handling
// ---------------------------------------------------------------------------

func TestToSecretAllFields(t *testing.T) {
	e := &Entry{
		Title:    "Test",
		Password: "pw",
		Username: "user",
		URL:      "https://example.com",
		TOTPURI:  "otpauth://totp/Test:?secret=ABC",
		Notes:    "some notes",
		Fields: []Field{
			{Name: "custom1", Value: "val1"},
			{Name: "custom2", Value: "val2"},
		},
	}
	sec := e.ToSecret()
	if sec.Password() != "pw" {
		t.Error("password")
	}
	if u, _ := sec.Field("username"); u != "user" {
		t.Error("username")
	}
	if u, _ := sec.Field("url"); u != "https://example.com" {
		t.Error("url")
	}
	if u, _ := sec.Field("custom1"); u != "val1" {
		t.Error("custom1")
	}
	if u, _ := sec.Field("custom2"); u != "val2" {
		t.Error("custom2")
	}
	if otp, _ := sec.OTP(); otp != "otpauth://totp/Test:?secret=ABC" {
		t.Error("otp")
	}
	if !strings.Contains(sec.Body(), "some notes") {
		t.Error("notes")
	}
}

func TestToSecretNotesTrailingNewline(t *testing.T) {
	e := &Entry{Password: "pw", Notes: "line1\n"}
	sec := e.ToSecret()
	// Should not double the newline.
	if strings.Contains(sec.Body(), "line1\n\n") {
		t.Error("double newline in notes")
	}
}

// ---------------------------------------------------------------------------
// csvReadAll: explicit encoding, invalid encoding, read error, UTF-16 BOM
// ---------------------------------------------------------------------------

func TestCSVReadAllWithEncoding(t *testing.T) {
	// "Проверка" in CP1251: П=0xCF р=0xF0 о=0xEE в=0xE2 е=0xE5 р=0xF0 к=0xEA а=0xE0
	cp1251Data := append([]byte("url,username,password\nhttps://test.com,user,"), 0xCF, 0xF0, 0xEE, 0xE2, 0xE5, 0xF0, 0xEA, 0xE0)
	rows, err := csvReadAll(bytes.NewReader(cp1251Data), "windows-1251")
	if err != nil {
		t.Fatalf("csvReadAll: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows: %d, want 2", len(rows))
	}
	if rows[1][2] == "" {
		t.Error("password should not be empty after decode")
	}
}

func TestCSVReadAllInvalidEncoding(t *testing.T) {
	_, err := csvReadAll(strings.NewReader("a,b\n1,2"), "invalid-encoding-xyz")
	if err == nil {
		t.Error("expected error for invalid encoding")
	}
}

func TestCSVReadAllReadError(t *testing.T) {
	_, err := csvReadAll(&errorReader{}, "")
	if err == nil {
		t.Error("expected error")
	}
}

type errorReader struct{}

func (errorReader) Read(_ []byte) (int, error) { return 0, fmt.Errorf("read error") }

func TestStripBOMUTF16(t *testing.T) {
	// UTF-16 LE BOM
	data := []byte{0xFF, 0xFE, 'a', ',', 'b', '\n', '1', ',', '2'}
	rows, err := csvReadAll(bytes.NewReader(data), "")
	if err != nil {
		t.Fatalf("csvReadAll UTF-16 LE: %v", err)
	}
	if len(rows) != 2 {
		t.Errorf("rows: %d", len(rows))
	}

	// UTF-16 BE BOM
	data2 := []byte{0xFE, 0xFF, 0x00, 'a', 0x00, ',', 0x00, 'b'}
	rows2, err2 := csvReadAll(bytes.NewReader(data2), "")
	// May not parse as valid CSV but should not panic.
	_ = rows2
	_ = err2
}

// ---------------------------------------------------------------------------
// KeePass import error paths (kdbx.go:44)
// ---------------------------------------------------------------------------

// encodeKDBX turns db into KDBX bytes in a temp file and returns the bytes.
func encodeKDBX(t *testing.T, db *gokeepasslib.Database) []byte {
	t.Helper()
	if err := db.LockProtectedEntries(); err != nil {
		t.Fatalf("LockProtectedEntries: %v", err)
	}
	var buf bytes.Buffer
	if err := gokeepasslib.NewEncoder(&buf).Encode(db); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	return buf.Bytes()
}

func TestKeePassImportBadPassword(t *testing.T) {
	db := gokeepasslib.NewDatabase(gokeepasslib.WithDatabaseKDBXVersion3())
	db.Credentials = gokeepasslib.NewPasswordCredentials("correct")
	entry := gokeepasslib.NewEntry()
	entry.Values = append(entry.Values, gokeepasslib.ValueData{Key: "Title", Value: gokeepasslib.V{Content: "Test"}})
	rootGroup := gokeepasslib.NewGroup()
	rootGroup.Name = "Root"
	rootGroup.Entries = append(rootGroup.Entries, entry)
	db.Content = &gokeepasslib.DBContent{Meta: &gokeepasslib.MetaData{}, Root: &gokeepasslib.RootData{Groups: []gokeepasslib.Group{rootGroup}}}

	raw := encodeKDBX(t, db)

	// Decode with wrong password.
	imp := &KeePassImporter{Password: "wrong"}
	entries, err := ImportAll(imp, bytes.NewReader(raw))
	if err == nil {
		t.Error("expected error for wrong password")
	}
	_ = entries
}

func TestKeePassImportEmptyDB(t *testing.T) {
	// An empty database (no entries in the root) imports without error and
	// yields nothing.
	db := gokeepasslib.NewDatabase(gokeepasslib.WithDatabaseKDBXVersion3())
	db.Credentials = gokeepasslib.NewPasswordCredentials("pw")
	// One empty root group keeps the encoder from tripping over a nil binary
	// pool while still giving the importer zero entries to yield.
	emptyRoot := gokeepasslib.NewGroup()
	emptyRoot.Name = "Root"
	db.Content = &gokeepasslib.DBContent{
		Meta: &gokeepasslib.MetaData{},
		Root: &gokeepasslib.RootData{Groups: []gokeepasslib.Group{emptyRoot}},
	}

	raw := encodeKDBX(t, db)

	imp := &KeePassImporter{Password: "pw"}
	entries, err := ImportAll(imp, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("ImportAll empty DB: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestKeePassImportNotKDBX(t *testing.T) {
	imp := &KeePassImporter{Password: "pw"}
	entries, err := ImportAll(imp, strings.NewReader("this is not a kdbx file"))
	if err == nil {
		t.Error("expected error for non-KDBX input")
	}
	_ = entries
}

// ---------------------------------------------------------------------------
// Registry.Detect no match (registry.go:49)
// ---------------------------------------------------------------------------

func TestRegistryDetectNoMatch(t *testing.T) {
	r := NewRegistry()
	imp := r.Detect([]byte("random text that no importer matches"))
	if imp != nil {
		t.Errorf("expected nil, got %q", imp.Name())
	}
}

// ---------------------------------------------------------------------------
// Firefox extractDomain (firefox.go:67)
// ---------------------------------------------------------------------------

func TestFirefoxExtractDomain(t *testing.T) {
	tests := []struct{ input, want string }{
		{"https://example.com/path", "example.com"},
		{"http://test.com:8080/thing", "test.com"},
		{"ftp://files.example.com/", "files.example.com"},
		{"https://example.com", "example.com"},
		{"", ""},
	}
	for _, tc := range tests {
		got := extractDomain(tc.input)
		if got != tc.want {
			t.Errorf("extractDomain(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Chrome Detect negative + descriptive header (chrome.go:19)
// ---------------------------------------------------------------------------

func TestChromeDetectNegative(t *testing.T) {
	imp := &ChromeImporter{}
	if imp.Detect(strings.NewReader("not,a,chrome,csv")) {
		t.Error("should not match")
	}
}

func TestChromeImportWithDescriptiveHeader(t *testing.T) {
	csv := "This is a descriptive line that Chrome sometimes adds\nname,url,username,password,note\nTwitter,https://twitter.com,alice,hunter2,my account"
	imp := &ChromeImporter{}
	entries, err := ImportAll(imp, strings.NewReader(csv))
	if err != nil {
		t.Fatalf("ImportAll: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d, want 1", len(entries))
	}
	if entries[0].Title != "Twitter" {
		t.Errorf("Title = %q", entries[0].Title)
	}
}

// ---------------------------------------------------------------------------
// Bitwarden "(null)" URL + normalizeTOTP (bitwarden.go)
// ---------------------------------------------------------------------------

func TestBitwardenNullURL(t *testing.T) {
	csv := `folder,favorite,type,name,login_username,login_password,login_uri
Social,0,login,Twitter,alice,hunter2,(null)`
	imp := &BitwardenImporter{}
	entries, _ := ImportAll(imp, strings.NewReader(csv))
	if len(entries) != 1 {
		t.Fatalf("got %d", len(entries))
	}
	if entries[0].URL != "" {
		t.Errorf("URL should be empty for (null), got %q", entries[0].URL)
	}
}

func TestNormalizeTOTPAlreadyOTPAuth(t *testing.T) {
	got := normalizeTOTP("otpauth://totp/Test:?secret=ABC")
	if got != "otpauth://totp/Test:?secret=ABC" {
		t.Errorf("should pass through, got %q", got)
	}
}

func TestNormalizeTOTPRawBase32(t *testing.T) {
	got := normalizeTOTP("JBSWY3DPEHPK3PXP")
	if !strings.Contains(got, "otpauth://") {
		t.Errorf("should wrap, got %q", got)
	}
	if !strings.Contains(got, "JBSWY3DPEHPK3PXP") {
		t.Errorf("should contain secret, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// Enpass group column fallback (enpass.go:53)
// ---------------------------------------------------------------------------

func TestEnpassGroupFallback(t *testing.T) {
	csv := `Title,User Name,Password,Web Site,Remarks,Group
Twitter,alice,hunter2,https://twitter.com,,Social`
	imp := &EnpassImporter{}
	entries, _ := ImportAll(imp, strings.NewReader(csv))
	if len(entries) != 1 {
		t.Fatalf("got %d", len(entries))
	}
	if entries[0].Group != "Social" {
		t.Errorf("Group = %q, want %q", entries[0].Group, "Social")
	}
}

// ---------------------------------------------------------------------------
// 1Password vault/category fallback (onepassword.go:50)
// ---------------------------------------------------------------------------

func TestOnePasswordVaultFallback(t *testing.T) {
	csv := `Title,Username,Password,URL,OTP,Notes,Vault
Entry,alice,pw,https://example.com,,,Work`
	imp := &OnePasswordImporter{}
	entries, _ := ImportAll(imp, strings.NewReader(csv))
	if len(entries) != 1 {
		t.Fatalf("got %d", len(entries))
	}
	if entries[0].Group != "Work" {
		t.Errorf("Group = %q, want %q", entries[0].Group, "Work")
	}
}

func TestOnePasswordCategoryFallback(t *testing.T) {
	csv := `Title,Username,Password,URL,OTP,Notes,Category
Entry,alice,pw,https://example.com,,,Finance`
	imp := &OnePasswordImporter{}
	entries, _ := ImportAll(imp, strings.NewReader(csv))
	if len(entries) != 1 {
		t.Fatalf("got %d", len(entries))
	}
	if entries[0].Group != "Finance" {
		t.Errorf("Group = %q, want %q", entries[0].Group, "Finance")
	}
}

// ---------------------------------------------------------------------------
// Plan with dedup within the import set (export.go:36)
// ---------------------------------------------------------------------------

func TestPlanWithDedup(t *testing.T) {
	s, _ := setupAgeStore(t)
	entries := []*Entry{
		{Title: "test", Password: "pw"},
		{Title: "test", Password: "pw2"}, // duplicate
	}
	plans := Plan(s, entries)
	if len(plans) != 2 {
		t.Fatalf("got %d plans", len(plans))
	}
	if plans[0].StorePath != "test" {
		t.Errorf("plan[0] = %q", plans[0].StorePath)
	}
	if plans[1].StorePath != "test-2" {
		t.Errorf("plan[1] = %q", plans[1].StorePath)
	}
}
