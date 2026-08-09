package importer

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/tobischo/gokeepasslib/v3"
)

// TestKeePassDetect verifies KDBX magic byte detection.
func TestKeePassDetect(t *testing.T) {
	imp := &KeePassImporter{}

	// KDBX magic bytes: 0x03, 0xd9, 0xa2, 0x96
	magic := []byte{0x03, 0xd9, 0xa2, 0x96, 0x67, 0xfb, 0x4b, 0xb5}
	if !imp.Detect(bytes.NewReader(magic)) {
		t.Error("KeePassImporter.Detect should recognise KDBX magic")
	}

	// Random data should not match.
	if imp.Detect(bytes.NewReader([]byte("not a kdbx file"))) {
		t.Error("KeePassImporter.Detect should not match random data")
	}

	// Too short.
	if imp.Detect(bytes.NewReader([]byte{0x03})) {
		t.Error("KeePassImporter.Detect should not match short input")
	}
}

// TestKeePassImportWithGeneratedDB creates a KDBX database in memory and
// verifies the importer can read it.
func TestKeePassImportWithGeneratedDB(t *testing.T) {
	password := "test-password-123"

	// Create a new database with one group and one entry.
	db := gokeepasslib.NewDatabase(gokeepasslib.WithDatabaseKDBXVersion3())
	db.Credentials = gokeepasslib.NewPasswordCredentials(password)

	entry := gokeepasslib.NewEntry()
	entry.Values = append(entry.Values,
		gokeepasslib.ValueData{Key: "Title", Value: gokeepasslib.V{Content: "TestEntry"}},
		gokeepasslib.ValueData{Key: "UserName", Value: gokeepasslib.V{Content: "alice"}},
		gokeepasslib.ValueData{Key: "Password", Value: gokeepasslib.V{Content: "hunter2"}},
		gokeepasslib.ValueData{Key: "URL", Value: gokeepasslib.V{Content: "https://example.com"}},
		gokeepasslib.ValueData{Key: "Notes", Value: gokeepasslib.V{Content: "test notes"}},
	)

	rootGroup := gokeepasslib.NewGroup()
	rootGroup.Name = "Root"
	rootGroup.Entries = append(rootGroup.Entries, entry)

	db.Content = &gokeepasslib.DBContent{
		Meta: &gokeepasslib.MetaData{},
		Root: &gokeepasslib.RootData{
			Groups: []gokeepasslib.Group{rootGroup},
		},
	}

	// Lock protected entries (encrypts the password field).
	if err := db.LockProtectedEntries(); err != nil {
		t.Fatalf("LockProtectedEntries: %v", err)
	}

	// Encode to buffer.
	var buf bytes.Buffer
	encoder := gokeepasslib.NewEncoder(&buf)
	if err := encoder.Encode(db); err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Write to temp file (KeePass importer needs to re-open for Import).
	tmpFile := filepath.Join(t.TempDir(), "test.kdbx")
	if err := os.WriteFile(tmpFile, buf.Bytes(), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Now import with KeePassImporter.
	imp := &KeePassImporter{Password: password}
	f, err := os.Open(tmpFile)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = f.Close() }()

	entries, err := ImportAll(imp, f)
	if err != nil {
		t.Fatalf("ImportAll: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}

	got := entries[0]
	if got.Title != "TestEntry" {
		t.Errorf("Title = %q, want %q", got.Title, "TestEntry")
	}
	if got.Username != "alice" {
		t.Errorf("Username = %q, want %q", got.Username, "alice")
	}
	if got.Password != "hunter2" {
		t.Errorf("Password = %q, want %q", got.Password, "hunter2")
	}
	if got.URL != "https://example.com" {
		t.Errorf("URL = %q, want %q", got.URL, "https://example.com")
	}
	if got.Notes != "test notes" {
		t.Errorf("Notes = %q, want %q", got.Notes, "test notes")
	}
}

func TestKeePassDetectNoMatch(t *testing.T) {
	imp := &KeePassImporter{}
	if imp.Detect(bytes.NewReader([]byte{0x01, 0x02, 0x03, 0x04})) {
		t.Error("should not match non-KDBX magic")
	}
}

// TestKeePassNestedGroups verifies recursive group traversal: entries in
// sub-groups and sub-sub-groups are found with the correct "." path.
func TestKeePassNestedGroups(t *testing.T) {
	password := "test-password-123"

	newEntry := func(title string) gokeepasslib.Entry {
		e := gokeepasslib.NewEntry()
		e.Values = append(e.Values,
			gokeepasslib.ValueData{Key: "Title", Value: gokeepasslib.V{Content: title}},
			gokeepasslib.ValueData{Key: "Password", Value: gokeepasslib.V{Content: "x"}},
		)
		return e
	}

	// Root/Finance/Bank
	finance := gokeepasslib.NewGroup()
	finance.Name = "Finance"
	finance.Entries = append(finance.Entries, newEntry("Bank"))

	// Root/Social/Mastodon/Account
	mastodon := gokeepasslib.NewGroup()
	mastodon.Name = "Mastodon"
	mastodon.Entries = append(mastodon.Entries, newEntry("Account"))

	social := gokeepasslib.NewGroup()
	social.Name = "Social"
	social.Groups = append(social.Groups, mastodon)

	rootGroup := gokeepasslib.NewGroup()
	// Empty root name: the importer prepends the top-level group name to
	// descendant paths, so leaving the root unnamed produces the exact
	// "Finance" and "Social/Mastodon" group paths.
	rootGroup.Name = ""
	rootGroup.Groups = append(rootGroup.Groups, finance, social)

	db := gokeepasslib.NewDatabase(gokeepasslib.WithDatabaseKDBXVersion3())
	db.Credentials = gokeepasslib.NewPasswordCredentials(password)
	db.Content = &gokeepasslib.DBContent{
		Meta: &gokeepasslib.MetaData{},
		Root: &gokeepasslib.RootData{Groups: []gokeepasslib.Group{rootGroup}},
	}

	if err := db.LockProtectedEntries(); err != nil {
		t.Fatalf("LockProtectedEntries: %v", err)
	}

	var buf bytes.Buffer
	if err := gokeepasslib.NewEncoder(&buf).Encode(db); err != nil {
		t.Fatalf("Encode: %v", err)
	}

	tmpFile := filepath.Join(t.TempDir(), "nested.kdbx")
	if err := os.WriteFile(tmpFile, buf.Bytes(), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	imp := &KeePassImporter{Password: password}
	f, err := os.Open(tmpFile)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = f.Close() }()

	entries, err := ImportAll(imp, f)
	if err != nil {
		t.Fatalf("ImportAll: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}

	got := map[string]string{}
	for _, e := range entries {
		got[e.Title] = e.Group
	}

	if got["Bank"] != "Finance" {
		t.Errorf("Bank path = %q, want %q", got["Bank"], "Finance")
	}
	if got["Account"] != "Social/Mastodon" {
		t.Errorf("Account path = %q, want %q", got["Account"], "Social/Mastodon")
	}
}

// TestKeePassTOTPFields verifies TOTP field handling: raw base32 secrets are
// wrapped into otpauth:// URIs, and pre-existing otpauth URIs are kept as-is.
func TestKeePassTOTPFields(t *testing.T) {
	password := "test-password-123"

	newEntry := func(title string, vals ...gokeepasslib.ValueData) gokeepasslib.Entry {
		e := gokeepasslib.NewEntry()
		e.Values = append(e.Values,
			gokeepasslib.ValueData{Key: "Title", Value: gokeepasslib.V{Content: title}},
		)
		e.Values = append(e.Values, vals...)
		return e
	}

	rootGroup := gokeepasslib.NewGroup()
	rootGroup.Name = "Root"
	rootGroup.Entries = append(rootGroup.Entries,
		newEntry("RawSecret",
			gokeepasslib.ValueData{Key: "TimeOtp-Secret-Base32", Value: gokeepasslib.V{Content: "JBSWY3DPEHPK3PXP"}},
		),
		newEntry("FullURI",
			gokeepasslib.ValueData{Key: "otp", Value: gokeepasslib.V{Content: "otpauth://totp/Test:alice?secret=HI"}},
		),
	)

	db := gokeepasslib.NewDatabase(gokeepasslib.WithDatabaseKDBXVersion3())
	db.Credentials = gokeepasslib.NewPasswordCredentials(password)
	db.Content = &gokeepasslib.DBContent{
		Meta: &gokeepasslib.MetaData{},
		Root: &gokeepasslib.RootData{Groups: []gokeepasslib.Group{rootGroup}},
	}

	if err := db.LockProtectedEntries(); err != nil {
		t.Fatalf("LockProtectedEntries: %v", err)
	}

	var buf bytes.Buffer
	if err := gokeepasslib.NewEncoder(&buf).Encode(db); err != nil {
		t.Fatalf("Encode: %v", err)
	}

	tmpFile := filepath.Join(t.TempDir(), "totp.kdbx")
	if err := os.WriteFile(tmpFile, buf.Bytes(), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	imp := &KeePassImporter{Password: password}
	f, err := os.Open(tmpFile)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = f.Close() }()

	entries, err := ImportAll(imp, f)
	if err != nil {
		t.Fatalf("ImportAll: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}

	byTitle := map[string]*Entry{}
	for i := range entries {
		byTitle[entries[i].Title] = entries[i]
	}

	wantRaw := "otpauth://totp/RawSecret:?secret=JBSWY3DPEHPK3PXP&issuer=RawSecret"
	if got := byTitle["RawSecret"].TOTPURI; got != wantRaw {
		t.Errorf("RawSecret TOTPURI = %q, want %q", got, wantRaw)
	}

	wantFull := "otpauth://totp/Test:alice?secret=HI"
	if got := byTitle["FullURI"].TOTPURI; got != wantFull {
		t.Errorf("FullURI TOTPURI = %q, want %q", got, wantFull)
	}
}

// TestKeePassCustomFields verifies that non-standard string fields are mapped
// into entry.Fields while standard fields (Title, UserName, Password, URL,
// Notes) are excluded.
func TestKeePassCustomFields(t *testing.T) {
	password := "test-password-123"

	entry := gokeepasslib.NewEntry()
	entry.Values = append(entry.Values,
		gokeepasslib.ValueData{Key: "Title", Value: gokeepasslib.V{Content: "MyEntry"}},
		gokeepasslib.ValueData{Key: "UserName", Value: gokeepasslib.V{Content: "alice"}},
		gokeepasslib.ValueData{Key: "Password", Value: gokeepasslib.V{Content: "hunter2"}},
		gokeepasslib.ValueData{Key: "URL", Value: gokeepasslib.V{Content: "https://example.com"}},
		gokeepasslib.ValueData{Key: "Notes", Value: gokeepasslib.V{Content: "some notes"}},
		gokeepasslib.ValueData{Key: "CustomField1", Value: gokeepasslib.V{Content: "value1"}},
		gokeepasslib.ValueData{Key: "CustomField2", Value: gokeepasslib.V{Content: "value2"}},
	)

	rootGroup := gokeepasslib.NewGroup()
	rootGroup.Name = "Root"
	rootGroup.Entries = append(rootGroup.Entries, entry)

	db := gokeepasslib.NewDatabase(gokeepasslib.WithDatabaseKDBXVersion3())
	db.Credentials = gokeepasslib.NewPasswordCredentials(password)
	db.Content = &gokeepasslib.DBContent{
		Meta: &gokeepasslib.MetaData{},
		Root: &gokeepasslib.RootData{Groups: []gokeepasslib.Group{rootGroup}},
	}

	if err := db.LockProtectedEntries(); err != nil {
		t.Fatalf("LockProtectedEntries: %v", err)
	}

	var buf bytes.Buffer
	if err := gokeepasslib.NewEncoder(&buf).Encode(db); err != nil {
		t.Fatalf("Encode: %v", err)
	}

	tmpFile := filepath.Join(t.TempDir(), "custom.kdbx")
	if err := os.WriteFile(tmpFile, buf.Bytes(), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	imp := &KeePassImporter{Password: password}
	f, err := os.Open(tmpFile)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = f.Close() }()

	entries, err := ImportAll(imp, f)
	if err != nil {
		t.Fatalf("ImportAll: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}

	got := entries[0]
	if len(got.Fields) != 2 {
		t.Fatalf("got %d custom fields, want 2: %v", len(got.Fields), got.Fields)
	}

	if got.Fields[0].Name != "CustomField1" || got.Fields[0].Value != "value1" {
		t.Errorf("Fields[0] = %+v, want {CustomField1 value1}", got.Fields[0])
	}
	if got.Fields[1].Name != "CustomField2" || got.Fields[1].Value != "value2" {
		t.Errorf("Fields[1] = %+v, want {CustomField2 value2}", got.Fields[1])
	}

	// Ensure standard fields did not leak into the custom fields slice.
	standard := []string{"Title", "UserName", "Password", "URL", "Notes"}
	for _, name := range standard {
		for _, f := range got.Fields {
			if f.Name == name {
				t.Errorf("standard field %q leaked into Fields", name)
			}
		}
	}
}

// TestKeePassAttachment verifies KDBX binary attachments are resolved from the
// database binary pool and mapped to entry attachments.
func TestKeePassAttachment(t *testing.T) {
	password := "test-password-123"

	db := gokeepasslib.NewDatabase(gokeepasslib.WithDatabaseKDBXVersion3())
	db.Credentials = gokeepasslib.NewPasswordCredentials(password)
	db.Content = &gokeepasslib.DBContent{
		Meta: &gokeepasslib.MetaData{},
		Root: &gokeepasslib.RootData{Groups: []gokeepasslib.Group{
			gokeepasslib.NewGroup(),
		}},
	}

	// Add a binary to the database pool (KDBX3: stored under Meta.Binaries).
	content := []byte("attachment-binary-content")
	binary := db.AddBinary(content)
	if binary == nil {
		t.Fatal("AddBinary returned nil")
	}

	entry := gokeepasslib.NewEntry()
	entry.Values = append(entry.Values,
		gokeepasslib.ValueData{Key: "Title", Value: gokeepasslib.V{Content: "WithAttach"}},
	)
	entry.Binaries = append(entry.Binaries, binary.CreateReference("secret.txt"))

	db.Content.Root.Groups[0].Name = "Root"
	db.Content.Root.Groups[0].Entries = append(db.Content.Root.Groups[0].Entries, entry)

	if err := db.LockProtectedEntries(); err != nil {
		t.Fatalf("LockProtectedEntries: %v", err)
	}

	var buf bytes.Buffer
	if err := gokeepasslib.NewEncoder(&buf).Encode(db); err != nil {
		t.Fatalf("Encode: %v", err)
	}

	tmpFile := filepath.Join(t.TempDir(), "attach.kdbx")
	if err := os.WriteFile(tmpFile, buf.Bytes(), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	imp := &KeePassImporter{Password: password}
	f, err := os.Open(tmpFile)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = f.Close() }()

	entries, err := ImportAll(imp, f)
	if err != nil {
		t.Fatalf("ImportAll: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}

	got := entries[0]
	if len(got.Attachments) != 1 {
		t.Fatalf("got %d attachments, want 1: %v", len(got.Attachments), got.Attachments)
	}
	if got.Attachments[0].Name != "secret.txt" {
		t.Errorf("attachment name = %q, want %q", got.Attachments[0].Name, "secret.txt")
	}
	if !bytes.Equal(got.Attachments[0].Data, content) {
		t.Errorf("attachment data = %q, want %q", got.Attachments[0].Data, content)
	}
}

// TestKeePassAttachmentUnresolved verifies graceful handling when an entry
// references a binary that is not present in the database pool: the attachment
// is skipped and the entry imports without error.
func TestKeePassAttachmentUnresolved(t *testing.T) {
	password := "test-password-123"

	entry := gokeepasslib.NewEntry()
	entry.Values = append(entry.Values,
		gokeepasslib.ValueData{Key: "Title", Value: gokeepasslib.V{Content: "DanglingRef"}},
	)
	// Reference binary ID 0 without adding it to the pool, so bin.Find(db)
	// returns nil and the importer must skip it.
	entry.Binaries = append(entry.Binaries, gokeepasslib.NewBinaryReference("missing.txt", 0))

	rootGroup := gokeepasslib.NewGroup()
	rootGroup.Name = "Root"
	rootGroup.Entries = append(rootGroup.Entries, entry)

	db := gokeepasslib.NewDatabase(gokeepasslib.WithDatabaseKDBXVersion3())
	db.Credentials = gokeepasslib.NewPasswordCredentials(password)
	db.Content = &gokeepasslib.DBContent{
		Meta: &gokeepasslib.MetaData{},
		Root: &gokeepasslib.RootData{Groups: []gokeepasslib.Group{rootGroup}},
	}

	if err := db.LockProtectedEntries(); err != nil {
		t.Fatalf("LockProtectedEntries: %v", err)
	}

	var buf bytes.Buffer
	if err := gokeepasslib.NewEncoder(&buf).Encode(db); err != nil {
		t.Fatalf("Encode: %v", err)
	}

	tmpFile := filepath.Join(t.TempDir(), "dangling.kdbx")
	if err := os.WriteFile(tmpFile, buf.Bytes(), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	imp := &KeePassImporter{Password: password}
	f, err := os.Open(tmpFile)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = f.Close() }()

	entries, err := ImportAll(imp, f)
	if err != nil {
		t.Fatalf("ImportAll: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}

	got := entries[0]
	if len(got.Attachments) != 0 {
		t.Fatalf("got %d attachments, want 0 (unresolved ref should be skipped): %v", len(got.Attachments), got.Attachments)
	}
	if got.Title != "DanglingRef" {
		t.Errorf("Title = %q, want %q", got.Title, "DanglingRef")
	}
}
