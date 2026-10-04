package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/71g3pf4c3/binpass/internal/config"
	"github.com/71g3pf4c3/binpass/pkg/crypto"
	"github.com/71g3pf4c3/binpass/pkg/secret"
	"github.com/71g3pf4c3/binpass/pkg/store"
	tea "github.com/charmbracelet/bubbletea"
)

// The editor is the part of the TUI where correctness is on-disk, not
// visual: every test here drives entryEditor (or the edit view handlers)
// and checks the resulting secret bytes, so a rendering regression can
// never be confused with a format regression.

func TestEntryEditorRoundTripUnmodified(t *testing.T) {
	tests := []struct {
		name      string
		plaintext string
	}{
		{"password only", "hunter2\n"},
		{"password and body", "hunter2\nusername: alice\nurl: https://example.com\n"},
		{"otpauth line", "pw\notpauth://totp/T:alice?secret=JBSWY3DPEHPK3PXP&period=30\n"},
		{"freeform notes", "pw\nline one\nline two\n"},
		{"mixed", "pw\nusername: alice\nnote\nurl: https://ex.io\notpauth://totp/T:a?secret=JBSWY3DPEHPK3PXP\ntail\n"},
		{"empty password", "\nusername: alice\n"},
		{"no trailing newline", "pw\nnote without newline"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEntryEditor(secret.Parse([]byte(tt.plaintext)))
			if e.dirty() {
				t.Error("freshly loaded editor must not be dirty")
			}
			if e.destructive() {
				t.Error("freshly loaded editor must not be destructive")
			}
			got := string(e.apply().Bytes())
			want := tt.plaintext
			if !strings.HasSuffix(want, "\n") {
				// secret.New always terminates the last line; pass
				// stores are newline-terminated by convention and the
				// editor normalises on write, not on read.
				want += "\n"
			}
			if got != want {
				t.Errorf("round-trip = %q, want %q", got, want)
			}
		})
	}
}

func TestEntryEditorEditPassword(t *testing.T) {
	e := newEntryEditor(secret.Parse([]byte("old\nusername: alice\n")))
	e.setPassword("new")
	if !e.dirty() || !e.destructive() {
		t.Error("password change must be dirty and destructive")
	}
	got := string(e.apply().Bytes())
	if got != "new\nusername: alice\n" {
		t.Errorf("apply = %q", got)
	}
}

func TestEntryEditorEditFieldValue(t *testing.T) {
	e := newEntryEditor(secret.Parse([]byte("pw\nusername: alice\nurl: https://old\n")))
	e.setValue(0, "bob") // rows[0] = "username: alice"
	e.setValue(1, "https://new")
	if !e.dirty() {
		t.Error("value edit must be dirty")
	}
	if e.destructive() {
		t.Error("value edit must not be destructive")
	}
	got := string(e.apply().Bytes())
	if got != "pw\nusername: bob\nurl: https://new\n" {
		t.Errorf("apply = %q", got)
	}
}

func TestEntryEditorRenameKey(t *testing.T) {
	e := newEntryEditor(secret.Parse([]byte("pw\nusername: alice\n")))
	e.setKey(0, "login")
	got := string(e.apply().Bytes())
	if got != "pw\nlogin: alice\n" {
		t.Errorf("apply = %q", got)
	}

	// A key with a colon or space would stop parsing as a field; the
	// editor must reject it before the line is staged.
	for _, bad := range []string{"", "has space", "has:colon"} {
		if validFieldKey(bad) {
			t.Errorf("validFieldKey(%q) must be false", bad)
		}
	}
	for _, good := range []string{"login", "url", "Login-2", "otp"} {
		if !validFieldKey(good) {
			t.Errorf("validFieldKey(%q) must be true", good)
		}
	}
}

func TestEntryEditorAddDeleteRows(t *testing.T) {
	e := newEntryEditor(secret.Parse([]byte("pw\nusername: alice\n")))
	e.addField("url", "https://ex.io")
	e.addNote("a note")
	e.deleteRow(0) // remove "username: alice"
	if !e.dirty() || !e.destructive() {
		t.Error("deletion must be dirty and destructive")
	}
	got := string(e.apply().Bytes())
	if got != "pw\nurl: https://ex.io\na note\n" {
		t.Errorf("apply = %q", got)
	}
}

func TestEntryEditorDeleteOutOfIndex(t *testing.T) {
	e := newEntryEditor(secret.Parse([]byte("pw\nnote\n")))
	e.deleteRow(5)
	e.deleteRow(-1)
	if e.dirty() {
		t.Error("out-of-range deletes must be no-ops")
	}
}

func TestEntryEditorAddOTPNote(t *testing.T) {
	e := newEntryEditor(secret.Parse([]byte("pw\n")))
	uri := "otpauth://totp/T:alice?secret=JBSWY3DPEHPK3PXP&period=30"
	e.addNote(uri)
	if len(e.rows) != 1 || !e.rows[0].otp {
		t.Fatal("otpauth note must be flagged")
	}
	// The applied secret must surface through the same OTP lookup the
	// detail view uses.
	if _, ok := e.apply().OTP(); !ok {
		t.Error("applied secret must expose the otpauth URI")
	}
}

// --- view-level editing flows ---

// editModel returns a model with the editor open on a known entry, backed
// by ms so saves are observable.
func editModel(t *testing.T, plaintext string) (Model, *mockStore) {
	t.Helper()
	ms := newMockStore(map[string]string{"entry": "pw"})
	// The mock maps values to password-only secrets; seed the real
	// plaintext so save/discard checks compare against what was opened.
	ms.entries["entry"] = secret.Parse([]byte(plaintext))
	cfg := config.Default()
	cfg.NoColor = true
	m, err := NewModel(Options{Store: ms, Cfg: cfg})
	if err != nil {
		t.Fatal(err)
	}
	m.SetSize(80, 24)
	m.openEntry("entry")
	m.sec = secret.Parse([]byte(plaintext))
	m.startEdit()
	if m.editor == nil || m.view != viewEdit {
		t.Fatal("startEdit must open the editor")
	}
	return m, ms
}

func key(r rune) tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}} }

// press sends a key to the model and returns the updated model, failing the
// test if Update panics.
func press(m Model, msg tea.KeyMsg) Model {
	mm, _ := m.Update(msg)
	return mm.(Model)
}

func TestEditViewEditFieldValue(t *testing.T) {
	m, ms := editModel(t, "pw\nusername: alice\n")

	// Select the username row (j once), edit its value (enter), retype.
	m = press(m, key('j'))
	m = press(m, tea.KeyMsg{Type: tea.KeyEnter})
	m = press(m, tea.KeyMsg{Type: tea.KeyCtrlU})
	for _, r := range "bob" {
		m = press(m, key(r))
	}
	m = press(m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.editMode != editBrowse {
		t.Fatalf("input mode after commit = %d, want browse", m.editMode)
	}

	// Save (shift+s): value edits are non-destructive, applied directly.
	m = press(m, key('S'))
	if got := ms.entries["entry"].String(); got != "pw\nusername: bob\n" {
		t.Errorf("store after save = %q", got)
	}
	if m.view != viewDetail {
		t.Errorf("view after save = %d, want detail", m.view)
	}
	if !strings.Contains(m.status, "saved") {
		t.Errorf("status = %q", m.status)
	}
}

func TestEditViewPasswordChangeAsksConfirm(t *testing.T) {
	m, ms := editModel(t, "oldpw\n")

	// Edit the password row (cursor already on row 0), replace, save.
	m = press(m, tea.KeyMsg{Type: tea.KeyEnter})
	m = press(m, tea.KeyMsg{Type: tea.KeyCtrlU})
	for _, r := range "newpw" {
		m = press(m, key(r))
	}
	m = press(m, tea.KeyMsg{Type: tea.KeyEnter})

	m = press(m, key('S'))
	if m.view != viewConfirm {
		t.Fatalf("destructive save must go through confirm, got view %d", m.view)
	}
	if m.confirmAction != "save-edit" {
		t.Errorf("confirmAction = %q", m.confirmAction)
	}
	if ms.set["entry"] != "" {
		t.Error("store must be untouched before confirmation")
	}

	// Decline (focus defaults to No): back to the editor, staged copy kept.
	m = press(m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.view != viewEdit || m.editor == nil {
		t.Fatalf("decline must return to the editor, view=%d", m.view)
	}
	if m.editor.password != "newpw" {
		t.Error("decline must not drop staged edits")
	}

	// Save again, confirm for real.
	m = press(m, key('S'))
	m.confirmFocus = 0
	m = press(m, tea.KeyMsg{Type: tea.KeyEnter})
	if got := ms.entries["entry"].Password(); got != "newpw" {
		t.Errorf("password after save = %q, want newpw", got)
	}
}

func TestEditViewAddFieldFlow(t *testing.T) {
	m, ms := editModel(t, "pw\n")

	// a → key input → value input → save.
	m = press(m, key('a'))
	for _, r := range "url" {
		m = press(m, key(r))
	}
	m = press(m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.editMode != editNewValue {
		t.Fatalf("mode after key = %d, want new-value", m.editMode)
	}
	for _, r := range "https://ex.io" {
		m = press(m, key(r))
	}
	m = press(m, tea.KeyMsg{Type: tea.KeyEnter})

	m = press(m, key('S'))
	if got := ms.entries["entry"].String(); got != "pw\nurl: https://ex.io\n" {
		t.Errorf("store after save = %q", got)
	}
}

func TestEditViewAddFieldBadKeyRejected(t *testing.T) {
	m, _ := editModel(t, "pw\n")

	m = press(m, key('a'))
	for _, r := range "bad key" {
		m = press(m, key(r))
	}
	m = press(m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.editMode != editNewKey {
		t.Error("space in key must keep the key input open")
	}
	if !strings.Contains(m.status, "key") {
		t.Errorf("status = %q, want key error", m.status)
	}
	if len(m.editor.rows) != 0 {
		t.Error("no row may be staged from an invalid key")
	}
}

func TestEditViewDeleteRowFlow(t *testing.T) {
	m, ms := editModel(t, "pw\nusername: alice\nurl: https://ex.io\n")

	// Delete the username row, save: destructive → confirm.
	m = press(m, key('j'))
	m = press(m, key('x'))
	m = press(m, key('S'))
	if m.view != viewConfirm {
		t.Fatal("row deletion must require confirmation")
	}
	m.confirmFocus = 0
	m = press(m, tea.KeyMsg{Type: tea.KeyEnter})
	if got := ms.entries["entry"].String(); got != "pw\nurl: https://ex.io\n" {
		t.Errorf("store after save = %q", got)
	}
}

func TestEditViewDiscardDirtyAsksConfirm(t *testing.T) {
	m, ms := editModel(t, "pw\nusername: alice\n")

	m = press(m, key('j'))
	m.editor.setValue(0, "bob")

	m = press(m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.view != viewConfirm || m.confirmAction != "discard-edit" {
		t.Fatalf("dirty escape must confirm, view=%d action=%q", m.view, m.confirmAction)
	}
	// Decline: back to the editor with edits intact.
	m = press(m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.view != viewEdit || m.editor.rows[0].value != "bob" {
		t.Error("declined discard must keep the editor open with edits")
	}
	// Confirm discard: no write happened.
	m = press(m, tea.KeyMsg{Type: tea.KeyEsc})
	m.confirmFocus = 0
	m = press(m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.view != viewDetail {
		t.Errorf("discard must return to detail, got view %d", m.view)
	}
	if got := ms.entries["entry"].String(); got != "pw\nusername: alice\n" {
		t.Errorf("store must be untouched after discard, got %q", got)
	}
}

func TestEditViewCleanEscapeReturns(t *testing.T) {
	m, _ := editModel(t, "pw\nusername: alice\n")
	m = press(m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.view != viewDetail {
		t.Errorf("clean escape must return to detail, got %d", m.view)
	}
	if m.editor != nil {
		t.Error("leaving the editor must clear the staged copy")
	}
}

func TestEditViewInputCancel(t *testing.T) {
	m, _ := editModel(t, "pw\nusername: alice\n")

	m = press(m, key('j'))
	m = press(m, tea.KeyMsg{Type: tea.KeyEnter})
	for _, r := range "zzz" {
		m = press(m, key(r))
	}
	m = press(m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.editMode != editBrowse {
		t.Error("esc must leave input mode")
	}
	if m.editor.rows[0].value != "alice" {
		t.Errorf("cancelled input must not change the row, got %q", m.editor.rows[0].value)
	}
}

func TestEditViewNoChangesSave(t *testing.T) {
	m, _ := editModel(t, "pw\nusername: alice\n")
	m = press(m, key('S'))
	if m.view != viewDetail {
		t.Errorf("saving without changes must return to detail, got %d", m.view)
	}
	if !strings.Contains(m.status, "no changes") {
		t.Errorf("status = %q", m.status)
	}
}

func TestEditViewRenderMasksPassword(t *testing.T) {
	m, _ := editModel(t, "hunter2\nusername: alice\n")
	view := m.View()
	if strings.Contains(view, "hunter2") {
		t.Errorf("editor must mask the password, got:\n%s", view)
	}
	m.showPass = true
	if !strings.Contains(m.View(), "hunter2") {
		t.Error("showPass must reveal the password in the editor")
	}
}

func TestEditViewFromDetailKey(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.openEntry("entry")
	m.sec = secret.New("pw", "username: alice")

	m2, _ := m.Update(key('e'))
	mm := m2.(Model)
	if mm.view != viewEdit || mm.editor == nil {
		t.Errorf("'e' in detail must open the editor, view=%d", mm.view)
	}

	// Without a decrypted secret the editor must not open.
	m3 := buildTestModel(map[string]string{"entry": "pw"})
	m3.openEntry("entry")
	m4, _ := m3.Update(key('e'))
	if m4.(Model).view != viewDetail {
		t.Error("'e' with nil secret must stay in detail")
	}
}

// --- on-disk round trip through a real store ---

// newRealStore builds an age-encrypted store in a temporary directory. The
// identity never leaves the test; the developer's own store, key ring and
// clipboard are not touched.
func newRealStore(t *testing.T) *store.Store {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "store")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	backend := crypto.NewAge(dir, func() ([]age.Identity, error) {
		return []age.Identity{id}, nil
	})
	s, err := store.New(store.Options{
		Dir:      dir,
		Backends: []crypto.Crypto{backend},
		Default:  backend,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Init("", []crypto.Recipient{crypto.Recipient(id.Recipient().String())}); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestEditorRealStoreRoundTrip(t *testing.T) {
	s := newRealStore(t)
	orig := "hunter2\nusername: alice\nurl: https://ex.io\nnote line\n"
	if err := s.Set("bank/card", secret.Parse([]byte(orig))); err != nil {
		t.Fatal(err)
	}

	sec, err := s.Get("bank/card")
	if err != nil {
		t.Fatal(err)
	}
	e := newEntryEditor(sec)
	e.setPassword("newpw")
	e.setValue(0, "bob") // username
	e.addField("otpauth-note", "x")
	e.deleteRow(2) // drop the freeform note (rows: username, url, note)
	if err := s.Set("bank/card", e.apply()); err != nil {
		t.Fatal(err)
	}

	back, err := s.Get("bank/card")
	if err != nil {
		t.Fatal(err)
	}
	want := "newpw\nusername: bob\nurl: https://ex.io\notpauth-note: x\n"
	if got := back.String(); got != want {
		t.Errorf("on-disk round trip = %q, want %q", got, want)
	}

	// The edited entry must still parse exactly the way pass reads it:
	// first line password, the rest as fields and notes.
	if back.Password() != "newpw" {
		t.Errorf("Password() = %q", back.Password())
	}
	if v, ok := back.Field("username"); !ok || v != "bob" {
		t.Errorf("Field(username) = %q, %v", v, ok)
	}
}

func TestEditorSaveRefreshesOTP(t *testing.T) {
	// Adding an otpauth line in the editor must arm the OTP timer on save,
	// exactly as opening an entry that already has one does.
	uri := "otpauth://totp/T:alice?secret=JBSWY3DPEHPK3PXP&period=30"
	m, _ := editModel(t, "pw\n")

	m = press(m, key('A'))
	for _, r := range uri {
		m = press(m, key(r))
	}
	m = press(m, tea.KeyMsg{Type: tea.KeyEnter})
	m = press(m, key('S'))

	if m.otpCfg == nil {
		t.Fatal("otpCfg must be set after saving an otpauth line")
	}
	if m.otpCode == "" {
		t.Error("otpCode must be computed after save")
	}
}
