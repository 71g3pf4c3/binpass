package cli

import (
	"encoding/csv"

	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/71g3pf4c3/binpass/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/encoding/charmap"
)

// --- csvEscape ---

func TestCSVEscape(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"simple", "simple"},
		{"with,comma", `"with,comma"`},
		{"with\"quote", `"with""quote"`},
		{"with\nnewline", "\"with\nnewline\""},
		{"with\r\ncrlf", "\"with\r\ncrlf\""},
		{"кириллица", "кириллица"},
		{"emoji 🎉", "emoji 🎉"},
	}
	for _, tc := range tests {
		got := csvEscape(tc.in)
		if got != tc.want {
			t.Errorf("csvEscape(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCSVEscapeMultibyte(t *testing.T) {
	// Russian text with comma — must be quoted, not double-encoded.
	got := csvEscape("Привет,мир")
	if !strings.HasPrefix(got, `"`) {
		t.Errorf("expected quoted result for multi-byte string with comma, got %q", got)
	}
}

// --- command construction ---

func TestNewImportCmd(t *testing.T) {
	cfg := config.Default()
	app := NewApp(cfg)
	cmd := newImportCmd(app)

	if cmd.Use == "" {
		t.Error("Use should not be empty")
	}
	if !cmd.HasFlags() {
		t.Error("import should have flags")
	}
	for _, name := range []string{"format", "dry-run", "force", "encoding"} {
		if f := cmd.Flags().Lookup(name); f == nil {
			t.Errorf("missing --%s flag", name)
		}
	}
}

func TestNewExportCmd(t *testing.T) {
	cfg := config.Default()
	app := NewApp(cfg)
	cmd := newExportCmd(app)

	if cmd.Use == "" {
		t.Error("Use should not be empty")
	}
	if f := cmd.Flags().Lookup("format"); f == nil {
		t.Error("missing --format flag")
	}
}

func TestNewAuditCmd(t *testing.T) {
	cfg := config.Default()
	app := NewApp(cfg)
	cmd := newAuditCmd(app)

	if cmd.Use == "" {
		t.Error("Use should not be empty")
	}
	for _, name := range []string{"format", "parallel", "no-hibp"} {
		if f := cmd.Flags().Lookup(name); f == nil {
			t.Errorf("missing --%s flag", name)
		}
	}
}

// --- runner tests, against a real store ---
//
// The runners below go through requireStore and the full age stack in a
// temporary directory, the same arrangement as the sync tests. A mock store
// would only restate the runner's own assumptions; the real one shows what
// `binpass import` actually does to a store.

// writeTempFile writes content to a file in a fresh temp directory and
// returns its path.
func writeTempFile(t *testing.T, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "input")
	require.NoError(t, os.WriteFile(path, content, 0o600))
	return path
}

func TestRunImport_WritesEntries(t *testing.T) {
	app := newTestApp(t)
	csv := `folder,favorite,type,name,login_username,login_password,login_uri,notes
Social,0,login,Twitter,@alice,hunter2,https://twitter.com,my account`
	path := writeTempFile(t, []byte(csv))

	require.NoError(t, app.runImport(path, "", false, false, ""))

	assert.Contains(t, app.out.String(), "Imported Social/Twitter")
	s, err := app.Store()
	require.NoError(t, err)
	sec, err := s.Get("Social/Twitter")
	require.NoError(t, err)
	assert.Equal(t, "hunter2", sec.Password())
}

func TestRunImport_DryRunWritesNothing(t *testing.T) {
	app := newTestApp(t)
	csv := `folder,favorite,type,name,login_username,login_password
Social,0,login,Twitter,@alice,hunter2`
	path := writeTempFile(t, []byte(csv))

	require.NoError(t, app.runImport(path, "", true, false, ""))

	assert.Contains(t, app.out.String(), "Import plan:")
	assert.Contains(t, app.out.String(), "Social/Twitter")
	names, err := app.Store()
	require.NoError(t, err)
	list, err := names.List("")
	require.NoError(t, err)
	assert.Empty(t, list, "a dry run must not write entries")
}

func TestRunImport_UnknownFormat(t *testing.T) {
	app := newTestApp(t)
	path := writeTempFile(t, []byte("url,username,password\n"))

	err := app.runImport(path, "kaboom", false, false, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown format "kaboom"`)
}

func TestRunImport_UndetectableFile(t *testing.T) {
	app := newTestApp(t)
	path := writeTempFile(t, []byte("neither a csv header\nnor anything known\n"))

	err := app.runImport(path, "", false, false, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not detect format")
}

func TestRunImport_ExistingEntryNeedsForce(t *testing.T) {
	app := newTestApp(t)
	app.set(t, "Social/Twitter", "old-password\n")
	csv := `folder,favorite,type,name,login_username,login_password
Social,0,login,Twitter,@alice,hunter2`
	path := writeTempFile(t, []byte(csv))

	// Without force the existing entry is refused, and left as it was.
	err := app.runImport(path, "", false, false, "")
	require.Error(t, err)
	assert.Contains(t, app.errText(), "already exists")
	s, err := app.Store()
	require.NoError(t, err)
	sec, err := s.Get("Social/Twitter")
	require.NoError(t, err)
	assert.Equal(t, "old-password", sec.Password())

	// With force it is replaced.
	require.NoError(t, app.runImport(path, "", false, true, ""))
	sec, err = s.Get("Social/Twitter")
	require.NoError(t, err)
	assert.Equal(t, "hunter2", sec.Password())
}

// err.out returns the diagnostics the runner printed to Err.
func (a *testApp) errText() string { return a.errOut.String() }

func TestRunImport_EncodingWindows1251(t *testing.T) {
	app := newTestApp(t)
	// A LastPass export written by a Russian Windows: the columns are
	// ASCII, the password is not. Encoded in CP1251, as the system would.
	lp := "url,username,password,extra,name,grouping,fav\n" +
		"https://bank.ru,alice,пароль,note,Банк,Работа,1"
	encoded, err := charmap.Windows1251.NewEncoder().Bytes([]byte(lp))
	require.NoError(t, err)
	path := writeTempFile(t, encoded)

	require.NoError(t, app.runImport(path, "lastpass", false, false, "windows-1251"))

	s, err := app.Store()
	require.NoError(t, err)
	sec, err := s.Get("Работа/Банк")
	require.NoError(t, err)
	assert.Equal(t, "пароль", sec.Password())
}

func TestRunExport_CSV(t *testing.T) {
	app := newTestApp(t)
	app.set(t, "github/alice", "hunter2\nusername: alice\nurl: https://github.com\n")
	app.set(t, "bank/x", "with,comma\n")

	require.NoError(t, app.runExport("csv", nil))

	out := app.out.String()
	assert.Contains(t, out, "path,username,password,url,otp,notes")
	assert.Contains(t, out, "github/alice,alice,hunter2,https://github.com,,")
	assert.Contains(t, out, `"with,comma"`, "a comma in a field must be quoted")
}

func TestRunExport_ToFile(t *testing.T) {
	app := newTestApp(t)
	app.set(t, "github/alice", "hunter2\n")
	target := filepath.Join(t.TempDir(), "export.csv")

	require.NoError(t, app.runExport("csv", []string{target}))

	data, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Contains(t, string(data), "github/alice,,hunter2")
}

func TestRunExport_SkipsUndecryptableEntry(t *testing.T) {
	app := newTestApp(t)
	app.set(t, "github/alice", "hunter2\n")
	// A file with a store extension but no valid ciphertext: on disk from
	// a failed write or a damaged sync, Get cannot decrypt it.
	require.NoError(t, os.WriteFile(filepath.Join(app.dir, "broken.age"), []byte("not ciphertext"), 0o600))

	require.NoError(t, app.runExport("csv", nil))

	assert.Contains(t, app.errOut.String(), "skip broken")
	assert.NotContains(t, app.out.String(), "broken", "the broken entry yields no CSV row")
	assert.Contains(t, app.out.String(), "github/alice")
}

func TestRunAudit_TextNoHIBP(t *testing.T) {
	app := newTestApp(t)
	app.set(t, "weak", "123456\n")
	app.set(t, "reused-one", "same-password-both-entries\n")
	app.set(t, "reused-two", "same-password-both-entries\n")

	require.NoError(t, app.runAudit(context.Background(), "text", 1, true, nil))

	out := app.out.String()
	assert.Contains(t, out, "weak")
	assert.Contains(t, out, "reused-one", "both reuse participants are reported")
	assert.Contains(t, out, "reused-two")
}

func TestRunAudit_JSON(t *testing.T) {
	app := newTestApp(t)
	app.set(t, "weak", "123456\n")

	require.NoError(t, app.runAudit(context.Background(), "json", 1, true, nil))

	var report map[string]any
	require.NoError(t, json.Unmarshal(app.out.Bytes(), &report))
	assert.NotNil(t, report["entries"], "the JSON report carries its findings")
}

func TestRunAudit_UnknownFormat(t *testing.T) {
	app := newTestApp(t)
	app.set(t, "weak", "123456\n")

	err := app.runAudit(context.Background(), "kaboom", 1, true, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown format "kaboom"`)
}

// fakeHIBP reports every password as breached, standing in for the network.
type fakeHIBP struct{}

func (fakeHIBP) Check(context.Context, string) (bool, error) { return true, nil }

// TestRunAudit_CriticalFindingsFailTheRun covers the exit code contract: an
// audit that finds breached passwords is a failed command, so scripts and
// CI stop on it. The breach database is injected — the real one is the
// network, which has no place in a test.
func TestRunAudit_CriticalFindingsFailTheRun(t *testing.T) {
	app := newTestApp(t)
	app.hibpClient = fakeHIBP{}
	app.set(t, "breached", "correct-horse-battery-staple\n")

	err := app.runAudit(context.Background(), "json", 1, false, nil)
	require.Error(t, err, "breached passwords must fail the audit run")
	assert.Contains(t, err.Error(), "critical finding")
}

// TestRunExport_NotesAreFreeForm covers the export roundtrip contract: the
// notes column carries the note lines, not a copy of the structured ones.
// With the whole body exported as notes, every re-import duplicated username
// and url — the body grew on each pass — while real note lines must survive.
func TestRunExport_NotesAreFreeForm(t *testing.T) {
	app := newTestApp(t)
	app.set(t, "site/login", "hunter2\nusername: alice\nurl: https://x.io\nremember: the answer\notpauth://totp/x?secret=JBSW\nplain note line\n")

	require.NoError(t, app.runExport("csv", nil))

	csv := app.out.String()
	assert.Contains(t, csv, ",alice,", "the username column")
	assert.Contains(t, csv, ",https://x.io,", "the url column")
	for _, want := range []string{"remember: the answer", "plain note line"} {
		assert.Contains(t, csv, want, "note material survives the export")
	}
	// username/url lines are columns now; as notes they would come back as
	// fields on re-import, duplicating themselves each pass.
	assert.NotContains(t, csv, "username: alice", "the field line is not also in notes")
	assert.NotContains(t, csv, "url: https://x.io", "the field line is not also in notes")
	assert.Equal(t, 1, strings.Count(csv, "otpauth://"), "the otp column carries the URI, and only it")
}

// TestRunExport_CRLFNoteRoundTrips checks the CRLF edge of csvEscape: a note
// written on Windows carries \r\n line endings, and some CSV readers choke
// on a CRLF inside a quoted field even though RFC 4180 allows it. The export
// normalises every field to LF — the note arrives as a clean multi-line
// field, and the export itself never emits a quoted CRLF.
func TestRunExport_CRLFNoteRoundTrips(t *testing.T) {
	app := newTestApp(t)
	app.set(t, "win/note", "hunter2\r\nusername: bob\r\nnote line\r\nsecond line\r\n")

	require.NoError(t, app.runExport("csv", nil))

	r := csv.NewReader(app.out)
	_, err := r.Read() // the header
	require.NoError(t, err, "our own export must parse as CSV")
	rec, err := r.Read()
	require.NoError(t, err, "our own export must parse as CSV")
	require.Len(t, rec, 6)
	assert.Equal(t, "win/note", rec[0])
	assert.Equal(t, "bob", rec[1], "the username column")
	assert.Equal(t, "note line\nsecond line", rec[5], "the note survives with normalised line endings")
	assert.NotContains(t, app.out.String(), "\r", "no carriage return is emitted inside a quoted field")
}

// TestRunAudit_PartialEntries covers --entries: the filter runs before
// decryption, so a partial audit costs a touch per requested entry, not per
// store entry — the difference between running it and not on a hardware token.
func TestRunAudit_PartialEntries(t *testing.T) {
	app := newTestApp(t)
	app.set(t, "bank/tinkoff", "hunter2\n")
	app.set(t, "bank/sber", "hunter2\n")
	app.set(t, "github/alice", "123456\n")

	// Only the bank entries: one glob, no per-name enumeration.
	require.NoError(t, app.runAudit(context.Background(), "text", 1, true, []string{"bank/*"}))

	assert.Contains(t, app.out.String(), "bank/tinkoff")
	assert.Contains(t, app.out.String(), "bank/sber")
	assert.NotContains(t, app.out.String(), "github/alice", "the filter keeps the rest of the store out")

	var report map[string]any
	app.out.Reset()
	require.NoError(t, app.runAudit(context.Background(), "json", 1, true, []string{"bank/*"}))
	require.NoError(t, json.Unmarshal(app.out.Bytes(), &report))
	stats, ok := report["stats"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, float64(2), stats["total"], "the stats count what was audited, not the whole store")
}
