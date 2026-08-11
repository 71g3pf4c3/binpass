package importer

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPassImporterDetect verifies that Detect always returns false: a pass
// store is identified by its directory structure, not by a single file's
// content, so stream-based detection is unsupported.
func TestPassImporterDetect(t *testing.T) {
	imp := PassImporter{}

	// Nil reader is the degenerate case; any content must also not match.
	if imp.Detect(nil) {
		t.Error("Detect(nil) should always return false")
	}
	if imp.Detect(bytes.NewReader(nil)) {
		t.Error("Detect(empty) should always return false")
	}
	if imp.Detect(bytes.NewReader([]byte("some pass-like content"))) {
		t.Error("Detect(content) should always return false for a directory-based format")
	}
}

// TestPassImporterEmptyDir verifies that an existing but empty directory
// yields no entries and no error.
func TestPassImporterEmptyDir(t *testing.T) {
	tmpDir := t.TempDir()

	imp := &PassImporter{Dir: tmpDir}
	entries, err := ImportAll(imp, nil)
	if err != nil {
		t.Fatalf("ImportAll on empty dir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("got %d entries, want 0", len(entries))
	}
}

// TestPassImporterMissingDir verifies that a nonexistent directory yields an
// error (filepath.Walk reports the read error from the root path).
func TestPassImporterMissingDir(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")

	imp := &PassImporter{Dir: missing}
	_, err := ImportAll(imp, nil)
	if err == nil {
		t.Fatal("ImportAll on missing dir should return an error")
	}
	if !strings.Contains(err.Error(), "does-not-exist") {
		t.Errorf("error %q should mention the missing path", err)
	}
}

// TestPassImporterWalk builds a representative pass store layout and verifies
// that only .gpg/.age files are imported, dotfiles and other files are skipped,
// and each entry carries the expected metadata plus the raw ciphertext.
func TestPassImporterWalk(t *testing.T) {
	tmpDir := t.TempDir()

	// Directory structure:
	//   .gpg-id                 skip (dotfile)
	//   Social/Twitter.gpg      import
	//   Finance/Bank.gpg        import
	//   Services/Cloud.age      import
	//   README.md               skip (not encrypted)
	//   .hidden.gpg             skip (dotfile, even though .gpg)
	mustMkdirAll(t, filepath.Join(tmpDir, "Social"))
	mustMkdirAll(t, filepath.Join(tmpDir, "Finance"))
	mustMkdirAll(t, filepath.Join(tmpDir, "Services"))

	mustWriteFile(t, filepath.Join(tmpDir, ".gpg-id"), []byte("recipient@example.com"))
	mustWriteFile(t, filepath.Join(tmpDir, "Social", "Twitter.gpg"), []byte("twitter-ciphertext"))
	mustWriteFile(t, filepath.Join(tmpDir, "Finance", "Bank.gpg"), []byte("bank-ciphertext"))
	mustWriteFile(t, filepath.Join(tmpDir, "Services", "Cloud.age"), []byte("cloud-ciphertext"))
	mustWriteFile(t, filepath.Join(tmpDir, "README.md"), []byte("store readme, not an entry"))
	mustWriteFile(t, filepath.Join(tmpDir, ".hidden.gpg"), []byte("should be skipped"))

	imp := &PassImporter{Dir: tmpDir}
	entries, err := ImportAll(imp, nil)
	if err != nil {
		t.Fatalf("ImportAll: %v", err)
	}

	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3: %+v", len(entries), entryPaths(entries))
	}

	// Map by path for deterministic assertions.
	byPath := map[string]*Entry{}
	for _, e := range entries {
		byPath[e.Path] = e
	}

	want := map[string]struct {
		data []byte
		ext  string
	}{
		"Social/Twitter": {data: []byte("twitter-ciphertext"), ext: ".gpg"},
		"Finance/Bank":   {data: []byte("bank-ciphertext"), ext: ".gpg"},
		"Services/Cloud": {data: []byte("cloud-ciphertext"), ext: ".age"},
	}

	for name, spec := range want {
		e, ok := byPath[name]
		if !ok {
			t.Errorf("missing entry for %q; got paths %v", name, entryPaths(entries))
			continue
		}

		// source-format field.
		if !hasField(e, "source-format", "pass") {
			t.Errorf("entry %q: missing/incorrect source-format field, got %v", name, e.Fields)
		}

		// source-ext field.
		if !hasField(e, "source-ext", spec.ext) {
			t.Errorf("entry %q: missing/incorrect source-ext field, got %v", name, e.Fields)
		}

		// Ciphertext attachment.
		if len(e.Attachments) != 1 {
			t.Fatalf("entry %q: got %d attachments, want 1", name, len(e.Attachments))
		}
		att := e.Attachments[0]
		wantName := "_ciphertext" + spec.ext
		if att.Name != wantName {
			t.Errorf("entry %q: attachment Name = %q, want %q", name, att.Name, wantName)
		}
		if !bytes.Equal(att.Data, spec.data) {
			t.Errorf("entry %q: attachment Data mismatch: got %q, want %q", name, att.Data, spec.data)
		}
	}
}

// TestPassImporterNoDir verifies that an importer with an empty Dir reports an
// error on the first yield rather than silently succeeding.
func TestPassImporterNoDir(t *testing.T) {
	imp := &PassImporter{}
	entries, err := ImportAll(imp, nil)
	if err == nil {
		t.Fatal("ImportAll with empty Dir should return an error")
	}
	if !strings.Contains(err.Error(), "source directory") {
		t.Errorf("error %q should mention the missing source directory", err)
	}
	if len(entries) != 0 {
		t.Errorf("got %d entries, want 0", len(entries))
	}
}

// --- helpers ---

func mustMkdirAll(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("MkdirAll(%q): %v", dir, err)
	}
}

func mustWriteFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("WriteFile(%q): %v", path, err)
	}
}

func hasField(e *Entry, name, value string) bool {
	for _, f := range e.Fields {
		if f.Name == name && f.Value == value {
			return true
		}
	}
	return false
}

func entryPaths(entries []*Entry) []string {
	paths := make([]string, 0, len(entries))
	for _, e := range entries {
		paths = append(paths, e.Path)
	}
	return paths
}
