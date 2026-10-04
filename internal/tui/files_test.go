package tui

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/71g3pf4c3/binpass/internal/config"
	"github.com/71g3pf4c3/binpass/pkg/binary"
	"github.com/71g3pf4c3/binpass/pkg/secret"
	tea "github.com/charmbracelet/bubbletea"
)

// Attachment correctness is on-disk: the tests drive the picker and the
// attach/extract commands and verify bytes, not pixels. Every filesystem
// touch happens inside t.TempDir().

// writeFile creates a file with the given content in a fresh directory and
// returns its path.
func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, name)
}

func TestListDir(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"zeta", "alpha", ".hidden-dir"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, dir, "zfile", []byte("z"))
	writeFile(t, dir, "afile", []byte("a"))
	writeFile(t, dir, ".dotfile", []byte("d"))

	got := listDir(dir)
	// Parent link first, then dirs sorted, then files sorted; dot-entries
	// never appear — a picker that surfaces ~/.gnupg by default would be
	// a hazard, not a feature.
	want := []string{"../", "alpha/", "zeta/", "afile", "zfile"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("listDir = %v, want %v", got, want)
	}
}

func TestListDirRootHasNoParent(t *testing.T) {
	// At the filesystem root the parent link must not appear (and must
	// not loop); tolerate environments where / is not readable by
	// skipping.
	ents, err := os.ReadDir("/")
	if err != nil {
		t.Skip("root not readable")
	}
	_ = ents
	got := listDir("/")
	for _, name := range got {
		if name == "../" {
			t.Fatal("listDir(/) must not include ../")
		}
	}
}

func TestDefaultBinName(t *testing.T) {
	tests := []struct {
		file, fromEntry, want string
	}{
		{"/home/u/photo.jpg", "", "photo.jpg.b64"},
		{"/home/u/key.b64", "", "key.b64"},
		{"/home/u/photo.jpg", "bank/card", "bank/card.b64"},
		{"/home/u/photo.jpg", "bank/card.b64", "photo.jpg.b64"}, // binary context must not cascade
	}
	for _, tt := range tests {
		if got := defaultBinName(tt.file, tt.fromEntry); got != tt.want {
			t.Errorf("defaultBinName(%q, %q) = %q, want %q", tt.file, tt.fromEntry, got, tt.want)
		}
	}
}

func TestBinStats(t *testing.T) {
	data := []byte("binary attachment stats payload")
	enc := base64.StdEncoding.EncodeToString(data)
	size, sum := binStats(secret.New(enc, ""))

	want := sha256.Sum256(data)
	if size != int64(len(data)) {
		t.Errorf("size = %d, want %d", size, len(data))
	}
	if sum != fmt.Sprintf("%x", want[:]) {
		t.Errorf("sum = %s, want %x", sum, want[:])
	}
}

func TestHumanSize(t *testing.T) {
	tests := []struct {
		n    int64
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{2048, "2.0 KiB"},
		{3 * 1024 * 1024, "3.0 MiB"},
	}
	for _, tt := range tests {
		if got := humanSize(tt.n); got != tt.want {
			t.Errorf("humanSize(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}

// --- attach/extract round trips through a real store ---

func TestAttachExtractRealStoreRoundTrip(t *testing.T) {
	s := newRealStore(t)
	srcDir := t.TempDir()
	data := []byte{0x00, 0xff, 0xfe, 0x81, 'a', 'b', 'c', 0x00, 0x42}
	src := writeFile(t, srcDir, "photo.jpg", data)

	// Wire a model over the real store, run the attach command.
	m, err := NewModel(Options{Store: s, Cfg: testConfig()})
	if err != nil {
		t.Fatal(err)
	}
	m.SetSize(80, 24)
	m.binFile = src
	m.binName = "bank/photo.b64"

	msg := m.attachCmd(src, "bank/photo.b64")()
	res, ok := msg.(binResult)
	if !ok || res.err != nil {
		t.Fatalf("attachCmd = %+v", msg)
	}
	if !s.Exists("bank/photo.b64") {
		t.Fatal("attachment entry not created")
	}
	// The stored plaintext must be exactly what the CLI would write:
	// one base64 line, decodable to the original bytes.
	sec, err := s.Get("bank/photo.b64")
	if err != nil {
		t.Fatal(err)
	}
	if sec.Password() != base64.StdEncoding.EncodeToString(data) {
		t.Errorf("stored base64 = %q", sec.Password())
	}

	// Extract to a fresh directory and compare bytes and checksum.
	outDir := t.TempDir()
	msg = m.extractCmd("bank/photo.b64", outDir)()
	res, ok = msg.(binResult)
	if !ok || res.err != nil {
		t.Fatalf("extractCmd = %+v", msg)
	}
	got, err := os.ReadFile(filepath.Join(outDir, "photo"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(data) {
		t.Errorf("extracted bytes differ: %x", got)
	}
	sum, err := binary.Sum(s, "bank/photo.b64")
	if err != nil {
		t.Fatal(err)
	}
	wantSum := sha256.Sum256(data)
	if sum != fmt.Sprintf("%x", wantSum[:]) {
		t.Errorf("sum = %s, want %x", sum, wantSum[:])
	}
}

func TestExtractRefusesOverwrite(t *testing.T) {
	s := newRealStore(t)
	srcDir := t.TempDir()
	data := []byte("v1")
	src := writeFile(t, srcDir, "doc", data)
	m, _ := NewModel(Options{Store: s, Cfg: testConfig()})
	m.SetSize(80, 24)

	if msg := m.attachCmd(src, "doc.b64")(); msg.(binResult).err != nil { //nolint:forcetypeassert // shape checked by the panic path.
		t.Fatal("attach failed")
	}

	outDir := t.TempDir()
	existing := writeFile(t, outDir, "doc", []byte("precious existing file"))

	msg := m.extractCmd("doc.b64", outDir)()
	res, ok := msg.(binResult)
	if !ok || res.err == nil {
		t.Fatalf("extraction over an existing file must fail, got %+v", msg)
	}
	// The existing file must be untouched.
	got, err := os.ReadFile(existing)
	if err != nil || string(got) != "precious existing file" {
		t.Errorf("existing file was damaged: %q, %v", got, err)
	}
}

// --- view flows over a mock store with real files ---

// pickerModel returns a model whose picker is open in srcDir with the
// given files, backed by a mock store.
func pickerModel(t *testing.T, ms *mockStore, srcDir string) Model {
	t.Helper()
	m, err := NewModel(Options{Store: ms, Cfg: testConfig()})
	if err != nil {
		t.Fatal(err)
	}
	m.SetSize(80, 24)
	m.binFrom = viewDetail
	m.binContext = "entry"
	m.filesDir = srcDir
	m.startFilePicker(false)
	if m.view != viewFiles {
		t.Fatal("picker did not open")
	}
	return m
}

func TestAttachFlowFromDetail(t *testing.T) {
	srcDir := t.TempDir()
	writeFile(t, srcDir, "zeta", []byte("z"))
	writeFile(t, srcDir, "alpha", []byte("a"))
	ms := newMockStore(map[string]string{"entry": "pw"})
	m := pickerModel(t, ms, srcDir)

	// Move past the parent link to the file, pick it, accept the name.
	m = press(m, tea.KeyMsg{Type: tea.KeyDown})
	m = press(m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.view != viewBinName {
		t.Fatalf("view after picking file = %d, want binName", m.view)
	}
	if m.binName != "entry.b64" { // named after the entry the flow started from
		t.Errorf("proposed name = %q, want entry.b64", m.binName)
	}
	m = press(m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.view != viewDetail {
		t.Fatalf("view after attach = %d, want detail", m.view)
	}

	// The async result must have stored a decodable entry.
	msg := m.attachCmd(m.binFile, m.binName)()
	if res := msg.(binResult); res.err != nil { //nolint:forcetypeassert // shape is fixed.
		t.Fatalf("attach result = %+v", res)
	}
	sec, ok := ms.entries["entry.b64"]
	if !ok {
		t.Fatal("entry.b64 missing from store")
	}
	decoded, err := base64.StdEncoding.DecodeString(sec.Password())
	if err != nil || string(decoded) != "a" {
		t.Errorf("stored content decodes to %q, %v", decoded, err)
	}
}

func TestPickerLettersGoToQueryOnceTyping(t *testing.T) {
	srcDir := t.TempDir()
	writeFile(t, srcDir, "alpha", []byte("a"))
	writeFile(t, srcDir, "zeta", []byte("z"))
	ms := newMockStore(map[string]string{"entry": "pw"})
	m := pickerModel(t, ms, srcDir)

	// Typing filters; once a query exists the navigation letters belong
	// to the query, while arrows keep navigating.
	m = press(m, key('a'))
	m = press(m, key('l'))
	if len(m.filesVis) != 1 || m.filesVis[0] != "alpha" {
		t.Fatalf("filtered rows = %v, want [alpha]", m.filesVis)
	}
	m = press(m, key('j'))
	m = press(m, key('k'))
	if m.filesQuery != "aljk" {
		t.Errorf("query = %q, want aljk", m.filesQuery)
	}

	// ctrl+u clears the query and restores full navigation.
	m = press(m, tea.KeyMsg{Type: tea.KeyCtrlU})
	if m.filesQuery != "" || len(m.filesVis) != 3 { // ../, alpha, zeta
		t.Errorf("after ctrl+u: query=%q rows=%v", m.filesQuery, m.filesVis)
	}
	m = press(m, key('j'))
	if m.filesCur != 1 {
		t.Errorf("after clearing the query j must navigate, cur=%d", m.filesCur)
	}
}

func TestAttachNameAutoSuffix(t *testing.T) {
	srcDir := t.TempDir()
	writeFile(t, srcDir, "blob", []byte("x"))
	ms := newMockStore(map[string]string{"entry": "pw"})
	m := pickerModel(t, ms, srcDir)

	m = press(m, tea.KeyMsg{Type: tea.KeyDown})
	m = press(m, tea.KeyMsg{Type: tea.KeyEnter}) // pick "blob"
	// Clear the proposed name, type one without the .b64 suffix.
	m = press(m, tea.KeyMsg{Type: tea.KeyCtrlU})
	for _, r := range "docs/key" {
		m = press(m, key(r))
	}
	m = press(m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.binName != "docs/key.b64" {
		t.Errorf("binName = %q, want docs/key.b64", m.binName)
	}
}

func TestAttachOverwriteAsksConfirm(t *testing.T) {
	srcDir := t.TempDir()
	writeFile(t, srcDir, "alpha", []byte("a"))
	ms := newMockStore(map[string]string{"entry": "pw"})
	ms.entries["entry.b64"] = secret.New(base64.StdEncoding.EncodeToString([]byte("old")), "")
	m := pickerModel(t, ms, srcDir)

	m = press(m, tea.KeyMsg{Type: tea.KeyDown})
	m = press(m, tea.KeyMsg{Type: tea.KeyEnter}) // pick alpha → name input
	m = press(m, tea.KeyMsg{Type: tea.KeyEnter}) // name exists → confirm
	if m.view != viewConfirm || m.confirmAction != "bin-overwrite" {
		t.Fatalf("overwrite must confirm, view=%d action=%q", m.view, m.confirmAction)
	}
	if m.confirmFocus != 1 {
		t.Error("overwrite confirm must default to No")
	}

	// Decline → back at the name input, store untouched.
	m = press(m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.view != viewBinName {
		t.Fatalf("decline must return to name input, got view %d", m.view)
	}
	sec := ms.entries["entry.b64"]
	if sec.Password() != base64.StdEncoding.EncodeToString([]byte("old")) {
		t.Error("declined overwrite must leave the entry alone")
	}
}

func TestPickerEscapeAndParent(t *testing.T) {
	sub := t.TempDir()
	srcDir := filepath.Join(sub, "inner")
	if err := os.MkdirAll(srcDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, srcDir, "f", []byte("x"))
	ms := newMockStore(map[string]string{"entry": "pw"})
	m := pickerModel(t, ms, srcDir)

	// h goes to the parent, whose listing contains inner/.
	m = press(m, key('h'))
	if m.filesDir != sub {
		t.Fatalf("after h, filesDir = %q, want %q", m.filesDir, sub)
	}
	if len(m.filesVis) == 0 || m.filesVis[0] != "../" {
		t.Errorf("parent listing = %v", m.filesVis)
	}

	// esc cancels back to where the flow started.
	m = press(m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.view != viewDetail {
		t.Errorf("esc from picker must return to the origin view, got %d", m.view)
	}
}

func TestBinaryDetailView(t *testing.T) {
	data := []byte("attachment body")
	ms := newMockStore(map[string]string{"photo.b64": "x"})
	ms.entries["photo.b64"] = secret.New(base64.StdEncoding.EncodeToString(data), "")

	m, err := NewModel(Options{Store: ms, Cfg: testConfig()})
	if err != nil {
		t.Fatal(err)
	}
	m.SetSize(80, 24)
	m.openEntry("photo.b64")
	if !m.binBackdrop {
		t.Fatal("opening a .b64 entry must set binBackdrop")
	}

	// Deliver the async unlock result: metadata is computed, not the body.
	updated, _ := m.Update(unlockResult{sec: ms.entries["photo.b64"]})
	m = updated.(Model)

	view := m.View()
	if !strings.Contains(view, "binary attachment") {
		t.Errorf("detail view must label the entry, got:\n%s", view)
	}
	if strings.Contains(view, base64.StdEncoding.EncodeToString(data)) {
		t.Errorf("detail view must not render the base64 body, got:\n%s", view)
	}
	want := sha256.Sum256(data)
	if !strings.Contains(view, fmt.Sprintf("%x", want[:])) {
		t.Errorf("detail view should show the sha256, got:\n%s", view)
	}

	// Text-only keys are refused with a hint, not silently mangled.
	m = press(m, key('e'))
	if m.view != viewDetail {
		t.Errorf("e on a binary entry must not open the editor, got %d", m.view)
	}
	if m.editor != nil {
		t.Error("editor must stay closed for binary entries")
	}

	// x starts the extraction destination picker.
	m = press(m, key('x'))
	if m.view != viewFiles || !m.pickDir {
		t.Errorf("x must open the dir picker, view=%d pickDir=%v", m.view, m.pickDir)
	}
}

// testConfig returns the shared no-colour config for view tests.
func testConfig() config.Config {
	cfg := config.Default()
	cfg.NoColor = true
	return cfg
}
