package importer

import (
	"bytes"
	"strings"
	"testing"
)

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		group string
		title string
		want  string
	}{
		{"", "github.com/alice", "github.com/alice"},
		{"Finance", "Tinkoff", "Finance/Tinkoff"},
		{"Finance/Banks", "Tinkoff", "Finance/Banks/Tinkoff"},
		{"", "My Secret", "My Secret"},
		{"", `entry<>:"|?*\`, "entry________"},
		{"", "  spaces  ", "spaces"},
		{"", "", ""},
		{"", "../etc/passwd", "etc/passwd"},
		{"", "..", ""},
		{"", ".", ""},
		{"Social/Mastodon", "Mastodon", "Social/Mastodon/Mastodon"},
	}

	for _, tc := range tests {
		t.Run(tc.group+"/"+tc.title, func(t *testing.T) {
			got := NormalizePath(tc.group, tc.title)
			if got != tc.want {
				t.Errorf("NormalizePath(%q, %q) = %q, want %q", tc.group, tc.title, got, tc.want)
			}
		})
	}
}

func TestValidatePath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"github.com/alice", true},
		{"bank/tinkoff", true},
		{"", false},
		{"/absolute", false},
		{"../etc/passwd", false},
		{"a//b", false},
		{"valid/path", true},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			got := ValidatePath(tc.path)
			if got != tc.want {
				t.Errorf("ValidatePath(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestDeduplicatePaths(t *testing.T) {
	paths := []string{"bank/tinkoff", "github/alice", "bank/tinkoff", "github/alice", "new"}
	got := DeduplicatePaths(paths)

	if len(got) != 5 {
		t.Fatalf("DeduplicatePaths returned %d entries, want 5", len(got))
	}
	// Unique entries keep their names.
	if got[4] != "new" {
		t.Errorf("got[4] = %q, want %q", got[4], "new")
	}
	// First occurrence keeps its name.
	if got[0] != "bank/tinkoff" {
		t.Errorf("got[0] = %q, want %q", got[0], "bank/tinkoff")
	}
	// Second occurrence gets "-2".
	if got[2] != "bank/tinkoff-2" {
		t.Errorf("got[2] = %q, want %q", got[2], "bank/tinkoff-2")
	}
	if got[3] != "github/alice-2" {
		t.Errorf("got[3] = %q, want %q", got[3], "github/alice-2")
	}
}

func TestBitwardenDetect(t *testing.T) {
	imp := &BitwardenImporter{}
	csv := `folder,favorite,type,name,login_username,login_password,login_uri,notes
Social,0,login,Twitter,@alice,hunter2,https://twitter.com,my account`
	if !imp.Detect(strings.NewReader(csv)) {
		t.Error("BitwardenImporter.Detect should recognise Bitwarden CSV")
	}
	if imp.Detect(strings.NewReader("random text")) {
		t.Error("BitwardenImporter.Detect should not match random text")
	}
}

func TestBitwardenImport(t *testing.T) {
	imp := &BitwardenImporter{}
	csv := `folder,favorite,type,name,login_username,login_password,login_uri,login_totp,notes
Social,0,login,Twitter,@alice,hunter2,https://twitter.com,,my account
Finance,0,login,Bank,alice,correct-horse-battery-staple,https://bank.com,JBSWY3DPEHPK3PXP,savings`

	entries, err := ImportAll(imp, strings.NewReader(csv))
	if err != nil {
		t.Fatalf("ImportAll: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}

	got := entries[0]
	if got.Title != "Twitter" {
		t.Errorf("Title = %q, want %q", got.Title, "Twitter")
	}
	if got.Username != "@alice" {
		t.Errorf("Username = %q, want %q", got.Username, "@alice")
	}
	if got.Password != "hunter2" {
		t.Errorf("Password = %q, want %q", got.Password, "hunter2")
	}
	if got.Group != "Social" {
		t.Errorf("Group = %q, want %q", got.Group, "Social")
	}

	got2 := entries[1]
	if got2.TOTPURI == "" {
		t.Error("TOTPURI should not be empty when login_totp is present")
	}
	if !strings.Contains(got2.TOTPURI, "otpauth://") {
		t.Errorf("TOTPURI = %q, should contain otpauth://", got2.TOTPURI)
	}
}

func TestBitwardenEmptyEntry(t *testing.T) {
	imp := &BitwardenImporter{}
	csv := `folder,favorite,type,name,login_username,login_password,login_uri
,0,note,,,,`

	entries, _ := ImportAll(imp, strings.NewReader(csv))
	if len(entries) != 0 {
		t.Errorf("empty entries should be skipped, got %d", len(entries))
	}
}

func TestOnePasswordDetect(t *testing.T) {
	imp := &OnePasswordImporter{}
	csv := `Title,Username,Password,URL,OTP,Notes
GitHub,alice,hunter2,https://github.com,,My account`
	if !imp.Detect(strings.NewReader(csv)) {
		t.Error("OnePasswordImporter.Detect should recognise 1Password CSV")
	}
}

func TestOnePasswordImport(t *testing.T) {
	imp := &OnePasswordImporter{}
	csv := `Title,Username,Password,URL,OTP,Notes
GitHub,alice,hunter2,https://github.com,otpauth://totp/GitHub:?secret=JBSWY3DPEHPK3PXP,My account`

	entries, err := ImportAll(imp, strings.NewReader(csv))
	if err != nil {
		t.Fatalf("ImportAll: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if entries[0].TOTPURI != "otpauth://totp/GitHub:?secret=JBSWY3DPEHPK3PXP" {
		t.Errorf("TOTPURI = %q, want otpauth URI", entries[0].TOTPURI)
	}
}

func TestLastPassDetect(t *testing.T) {
	imp := &LastPassImporter{}
	csv := `url,username,password,extra,name,grouping,fav
https://twitter.com,@alice,hunter2,notes,Twitter,Social,0`
	if !imp.Detect(strings.NewReader(csv)) {
		t.Error("LastPassImporter.Detect should recognise LastPass CSV")
	}
}

func TestLastPassSecureNote(t *testing.T) {
	imp := &LastPassImporter{}
	csv := `url,username,password,extra,name,grouping,fav
http://sn,,,my secret note,My Note,,0`

	entries, _ := ImportAll(imp, strings.NewReader(csv))
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if entries[0].URL != "" {
		t.Errorf("http://sn should be stripped, got URL = %q", entries[0].URL)
	}
}

func TestChromeDetect(t *testing.T) {
	imp := &ChromeImporter{}
	csv := `name,url,username,password,note
Twitter,https://twitter.com,alice,hunter2,`
	if !imp.Detect(strings.NewReader(csv)) {
		t.Error("ChromeImporter.Detect should recognise Chrome CSV")
	}
}

func TestChromeImport(t *testing.T) {
	imp := &ChromeImporter{}
	csv := `name,url,username,password,note
Twitter,https://twitter.com,alice,hunter2,my account`

	entries, _ := ImportAll(imp, strings.NewReader(csv))
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if entries[0].Title != "Twitter" {
		t.Errorf("Title = %q, want %q", entries[0].Title, "Twitter")
	}
}

func TestFirefoxDetect(t *testing.T) {
	imp := &FirefoxImporter{}
	csv := `url,username,password,httpRealm,formActionOrigin,guid,timeCreated
https://twitter.com,alice,hunter2,,,,`

	if !imp.Detect(strings.NewReader(csv)) {
		t.Error("FirefoxImporter.Detect should recognise Firefox CSV")
	}
}

func TestFirefoxImport(t *testing.T) {
	imp := &FirefoxImporter{}
	csv := `url,username,password,httpRealm,formActionOrigin,guid,timeCreated
https://bank.com,alice,correct-horse-battery-staple,,,,`

	entries, _ := ImportAll(imp, strings.NewReader(csv))
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if entries[0].Title != "bank.com" {
		t.Errorf("Title = %q, want %q", entries[0].Title, "bank.com")
	}
}

func TestEnpassDetect(t *testing.T) {
	imp := &EnpassImporter{}
	csv := `Title,User Name,Password,Web Site,Remarks,Category
Twitter,alice,hunter2,https://twitter.com,my account,Social`
	if !imp.Detect(strings.NewReader(csv)) {
		t.Error("EnpassImporter.Detect should recognise Enpass CSV")
	}
}

func TestEnpassSkipsRecycleBin(t *testing.T) {
	imp := &EnpassImporter{}
	csv := `Title,User Name,Password,Web Site,Remarks,Category
Twitter,alice,hunter2,https://twitter.com,,Social
Old,alice,oldpassword,https://old.com,,Recycle Bin`

	entries, _ := ImportAll(imp, strings.NewReader(csv))
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1 (recycle bin filtered)", len(entries))
	}
}

func TestCSVWithBOM(t *testing.T) {
	// UTF-8 BOM followed by a Bitwarden CSV.
	bom := []byte{0xEF, 0xBB, 0xBF}
	csv := append(bom, []byte(`folder,favorite,type,name,login_username,login_password,login_uri
Social,0,login,Twitter,@alice,hunter2,https://twitter.com`)...)

	imp := &BitwardenImporter{}
	entries, err := ImportAll(imp, bytes.NewReader(csv))
	if err != nil {
		t.Fatalf("ImportAll with BOM: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
}

func TestCSVNonUTF8(t *testing.T) {
	// A CSV in windows-1251 encoding (Cyrillic).
	// "Имя" in CP1251 = 0xC8 0xEC 0xFF
	cp1251Header := []byte{0xC8, 0xEC, 0xFF} // Cyrillic "Имя"
	cp1251Body := []byte("password")
	// Build a minimal CSV with cp1251 bytes.
	// This tests the decodeBytes fallback path.
	_ = cp1251Header
	_ = cp1251Body

	// More practical: create a LastPass-like CSV where the name field
	// contains Cyrillic in CP1251.
	// "Тест" in CP1251 = 0xD2 0xE5 0xF1 0xF2
	// Build the CSV bytes directly in CP1251.
	// url,username,password,extra,name,grouping,fav
	header := "url,username,password,extra,name,grouping,fav\n"
	row := "https://test.com,user,pass123,notes,"
	// Cyrillic "Тест" in CP1251
	rowCP1251 := append([]byte(row), 0xD2, 0xE5, 0xF1, 0xF2)
	rowCP1251 = append(rowCP1251, ",test,0\n"...)
	csvCP1251 := append([]byte(header), rowCP1251...)

	imp := &LastPassImporter{}
	entries, err := ImportAll(imp, bytes.NewReader(csvCP1251))
	if err != nil {
		t.Fatalf("ImportAll with CP1251: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	// The name should be decoded to UTF-8.
	if entries[0].Title == "" {
		t.Error("Title should not be empty after CP1251 decode")
	}
}

func TestCSVMultilineField(t *testing.T) {
	csv := `folder,favorite,type,name,login_username,login_password,login_uri,notes
Social,0,login,Twitter,@alice,hunter2,https://twitter.com,"line1
line2
line3"`

	imp := &BitwardenImporter{}
	entries, err := ImportAll(imp, strings.NewReader(csv))
	if err != nil {
		t.Fatalf("ImportAll with multiline: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if !strings.Contains(entries[0].Notes, "line1") {
		t.Errorf("multiline notes not preserved: %q", entries[0].Notes)
	}
}

func TestRegistryDetect(t *testing.T) {
	r := NewRegistry()

	bwCSV := `folder,favorite,type,name,login_username,login_password,login_uri
Social,0,login,Twitter,@alice,hunter2,https://twitter.com`
	imp, peek, err := r.DetectReader(strings.NewReader(bwCSV))
	if err != nil {
		t.Fatalf("DetectReader: %v", err)
	}
	if imp == nil {
		t.Fatal("DetectReader should detect Bitwarden CSV")
	}
	if imp.Name() != "Bitwarden" {
		t.Errorf("detected as %q, want %q", imp.Name(), "Bitwarden")
	}
	if len(peek) == 0 {
		t.Error("peek should contain bytes")
	}
}

func TestRegistryByName(t *testing.T) {
	r := NewRegistry()
	imp := r.ByName("KeePass")
	if imp == nil {
		t.Fatal("ByName should find KeePass")
	}
	if imp.Name() != "KeePass" {
		t.Errorf("Name = %q, want %q", imp.Name(), "KeePass")
	}
	if r.ByName("NonExistent") != nil {
		t.Error("ByName should return nil for unknown format")
	}
}

func TestEntryToSecret(t *testing.T) {
	e := &Entry{
		Title:    "GitHub",
		Username: "alice",
		Password: "hunter2",
		URL:      "https://github.com",
		TOTPURI:  "otpauth://totp/GitHub:?secret=JBSWY3DPEHPK3PXP",
		Notes:    "My account",
	}

	sec := e.ToSecret()
	if sec.Password() != "hunter2" {
		t.Errorf("Password = %q, want %q", sec.Password(), "hunter2")
	}
	u, ok := sec.Field("username")
	if !ok || u != "alice" {
		t.Errorf("username field = %q, ok = %v, want %q", u, ok, "alice")
	}
	url, ok := sec.Field("url")
	if !ok || url != "https://github.com" {
		t.Errorf("url field = %q, ok = %v, want %q", url, ok, "https://github.com")
	}
	otp, ok := sec.OTP()
	if !ok || otp != "otpauth://totp/GitHub:?secret=JBSWY3DPEHPK3PXP" {
		t.Errorf("OTP = %q, ok = %v", otp, ok)
	}
}

func TestEntryStorePath(t *testing.T) {
	e := &Entry{Title: "GitHub", Group: "Work"}
	p, err := e.StorePath()
	if err != nil {
		t.Fatalf("StorePath: %v", err)
	}
	if p != "Work/GitHub" {
		t.Errorf("StorePath = %q, want %q", p, "Work/GitHub")
	}

	// Explicit Path overrides Title+Group.
	e2 := &Entry{Title: "GitHub", Group: "Work", Path: "custom/path"}
	p2, err := e2.StorePath()
	if err != nil {
		t.Fatalf("StorePath: %v", err)
	}
	if p2 != "custom/path" {
		t.Errorf("StorePath = %q, want %q", p2, "custom/path")
	}
}

func TestEntryStorePathTraversal(t *testing.T) {
	e := &Entry{Path: "../etc/passwd"}
	_, err := e.StorePath()
	if err == nil {
		t.Error("StorePath should reject path traversal")
	}
}

func TestAttachmentStorePath(t *testing.T) {
	e := &Entry{
		Title: "doc",
		Attachments: []Attachment{
			{Name: "file.pdf", Data: []byte("fake pdf content")},
		},
	}
	p, err := e.AttachmentStorePath(0)
	if err != nil {
		t.Fatalf("AttachmentStorePath: %v", err)
	}
	if p != "doc/file.pdf.b64" {
		t.Errorf("AttachmentStorePath = %q, want %q", p, "doc/file.pdf.b64")
	}

	// Out-of-range index.
	_, err = e.AttachmentStorePath(1)
	if err == nil {
		t.Error("AttachmentStorePath should reject out-of-range index")
	}
}

func TestFormatPlan(t *testing.T) {
	plans := []PlanEntry{
		{StorePath: "bank/tinkoff", HasPassword: true, Conflict: false},
		{StorePath: "github/alice", HasPassword: true, HasTOTP: true, AttachmentCount: 2, Conflict: true},
	}
	out := FormatPlan(plans)
	if !strings.Contains(out, "bank/tinkoff") {
		t.Error("FormatPlan should contain entry name")
	}
	if !strings.Contains(out, "OVERWRITE") {
		t.Error("FormatPlan should show OVERWRITE for conflicts")
	}
	if !strings.Contains(out, "totp") {
		t.Error("FormatPlan should show TOTP flag")
	}
	if !strings.Contains(out, "2 attachments") {
		t.Error("FormatPlan should show attachment count")
	}
}

func TestRegistryImporters(t *testing.T) {
	r := NewRegistry()
	all := r.Importers()
	if len(all) < 8 {
		t.Errorf("Importers returned %d, want >= 8", len(all))
	}
	// Should be sorted by name.
	for i := 1; i < len(all); i++ {
		if all[i].Name() < all[i-1].Name() {
			t.Errorf("Importers not sorted: %q before %q", all[i-1].Name(), all[i].Name())
		}
	}
}

func TestB64Encode(t *testing.T) {
	data := []byte("hello world")
	got := b64Encode(data)
	if got != "aGVsbG8gd29ybGQ=" {
		t.Errorf("b64Encode = %q, want %q", got, "aGVsbG8gd29ybGQ=")
	}
}
