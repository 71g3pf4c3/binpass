package importer

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/71g3pf4c3/binpass/pkg/crypto"
	"github.com/71g3pf4c3/binpass/pkg/secret"
	"github.com/71g3pf4c3/binpass/pkg/store"
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

// entryPaths lists the store paths of entries, for failure messages.
func entryPaths(entries []*Entry) []string {
	paths := make([]string, 0, len(entries))
	for _, e := range entries {
		paths = append(paths, e.Path)
	}
	return paths
}

// --- decryption through a source store ---

// gpgTestUID identifies the throwaway key generated for importer tests.
const gpgTestUID = "binpass-import-test@example.invalid"

// newGPGTestHome generates an unprotected throwaway key in an isolated
// GNUPGHOME and returns its recipient. Decryption cannot be faked with
// builtins-only stubs, so these tests drive the real gpg binary; when it is
// absent they skip, the same precedent as the golden suite. The developer's
// own keyring is never touched.
func newGPGTestHome(t *testing.T) crypto.Recipient {
	t.Helper()
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not on PATH: cannot exercise pass importer decryption")
	}
	// GNUPGHOME lives under /tmp: gpg-agent's socket path is limited to
	// ~108 bytes and long TMPDIR-derived paths silently break the agent.
	home, err := os.MkdirTemp("", "binpass-importer-gnupg-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Setenv("GNUPGHOME", home)
	t.Cleanup(func() {
		_ = exec.Command("gpgconf", "--homedir", home, "--kill", "all").Run() //nolint:gosec // fixed arguments in tests.
		_ = os.RemoveAll(home)
	})

	gen := exec.Command("gpg", "--batch", "--passphrase", "", "--quick-generate-key", gpgTestUID, "default", "default", "never") //nolint:gosec // fixed arguments in tests.
	gen.Env = append(os.Environ(), "GNUPGHOME="+home)
	if out, err := gen.CombinedOutput(); err != nil {
		t.Skipf("cannot generate a test gpg key: %v: %s", err, out)
	}
	return crypto.Recipient(gpgTestUID)
}

// newPassSourceStore builds a real gpg-encrypted pass store in a temp
// directory and returns a store over it plus the directory path.
func newPassSourceStore(t *testing.T, entries map[string]string) (*store.Store, string) {
	t.Helper()
	rcp := newGPGTestHome(t)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".gpg-id"), []byte(rcp.String()+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile .gpg-id: %v", err)
	}
	g := crypto.NewGPG(dir, "", nil)
	for name, plain := range entries {
		path := filepath.Join(dir, filepath.FromSlash(name)+".gpg")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		f, err := os.Create(path) //nolint:gosec // path is derived from the test's own temp dir.
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := g.Encrypt(f, []byte(plain), []crypto.Recipient{rcp}); err != nil {
			t.Fatalf("Encrypt %s: %v", name, err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}

	// The age backend has no identities here; the source entries are .gpg,
	// which the gpg backend handles.
	src, err := store.New(store.Options{
		Dir:      dir,
		Backends: []crypto.Crypto{g, crypto.NewAge(dir, nil)},
		Default:  g,
	})
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	return src, dir
}

// TestPassImporterDecryptsViaSource verifies that with a Source store bound,
// entries are decrypted rather than carried as ciphertext: the password is
// populated, the raw plaintext survives verbatim, and no fallback attachment
// or source-format metadata is added.
func TestPassImporterDecryptsViaSource(t *testing.T) {
	plaintext := "hunter2\nusername: alice\notpauth://totp/x?secret=JBSWY3DP\n"
	src, dir := newPassSourceStore(t, map[string]string{"Social/Twitter": plaintext})

	imp := &PassImporter{Dir: dir, Source: src}
	entries, err := ImportAll(imp, nil)
	if err != nil {
		t.Fatalf("ImportAll: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}

	e := entries[0]
	if e.Path != "Social/Twitter" {
		t.Errorf("Path = %q, want %q", e.Path, "Social/Twitter")
	}
	if e.Password != "hunter2" {
		t.Errorf("Password = %q, want %q", e.Password, "hunter2")
	}
	if e.Raw == nil || !bytes.Equal(e.Raw.Bytes(), []byte(plaintext)) {
		t.Errorf("Raw must carry the source plaintext verbatim, got %q", e.Raw)
	}
	if len(e.Attachments) != 0 {
		t.Errorf("decrypted entry must not carry a ciphertext attachment, got %d", len(e.Attachments))
	}
	if len(e.Fields) != 0 {
		t.Errorf("decrypted entry must not carry source-format metadata, got %v", e.Fields)
	}

	// ToSecret must pass the raw secret through, not rebuild it: rebuilding
	// would reorder the body and drop free-form lines.
	if got := e.ToSecret().Bytes(); !bytes.Equal(got, []byte(plaintext)) {
		t.Errorf("ToSecret = %q, want the verbatim source plaintext %q", got, plaintext)
	}
}

// TestPassImporterDecryptFailureFallsBack verifies that an entry the source
// store cannot decrypt still arrives, as ciphertext attachment, and that the
// failure does not abort the walk.
func TestPassImporterDecryptFailureFallsBack(t *testing.T) {
	src, dir := newPassSourceStore(t, nil)

	// A .gpg file that is not valid OpenPGP data: decryption fails, reading
	// succeeds.
	if err := os.WriteFile(filepath.Join(dir, "Broken.gpg"), []byte("not openpgp data"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	imp := &PassImporter{Dir: dir, Source: src}
	entries, err := ImportAll(imp, nil)
	if err != nil {
		t.Fatalf("ImportAll must not abort on a single undecryptable entry: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}

	e := entries[0]
	if e.Path != "Broken" {
		t.Errorf("Path = %q, want %q", e.Path, "Broken")
	}
	if len(e.Attachments) != 1 || e.Attachments[0].Name != "_ciphertext.gpg" {
		t.Fatalf("undecryptable entry must fall back to a ciphertext attachment, got %+v", e.Attachments)
	}
	if !bytes.Equal(e.Attachments[0].Data, []byte("not openpgp data")) {
		t.Errorf("attachment must carry the raw ciphertext verbatim")
	}
}

// TestGopassImporterRegistry verifies that the gopass format name resolves to
// the gopass importer, which shares the pass implementation.
func TestGopassImporterRegistry(t *testing.T) {
	r := NewRegistry()
	imp := r.ByName("gopass")
	if imp == nil {
		t.Fatal("ByName(gopass) must resolve; the CLI advertises the format")
	}
	if imp.Name() != "gopass" {
		t.Errorf("Name = %q, want %q", imp.Name(), "gopass")
	}
	if _, ok := imp.(*GopassImporter); !ok {
		t.Errorf("gopass format must be served by GopassImporter, got %T", imp)
	}
	if r.ByName("pass") == nil {
		t.Error("ByName(pass) must still resolve")
	}
}

// TestToSecretRawPassthrough pins the contract that Raw, when set, wins over
// the structured fields: a rebuilt body would silently rewrite transferred
// entries.
func TestToSecretRawPassthrough(t *testing.T) {
	raw := secret.Parse([]byte("pw\nusername: alice\narbitrary line order\n"))
	e := &Entry{
		Password: "ignored",
		Username: "ignored",
		Raw:      raw,
	}
	if got := e.ToSecret(); got != raw {
		t.Errorf("ToSecret must return Raw unchanged, got %q", got)
	}
}
