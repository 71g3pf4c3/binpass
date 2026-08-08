package tui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/71g3pf4c3/binpass/internal/config"
	"github.com/71g3pf4c3/binpass/pkg/otp"
	"github.com/71g3pf4c3/binpass/pkg/secret"
	"github.com/71g3pf4c3/binpass/pkg/vcs"
	tea "github.com/charmbracelet/bubbletea"
)

// parseOTP is an alias for otp.Parse in tests.
var parseOTP = otp.Parse

// mockStore implements the tui.Store interface for tests.
type mockStore struct {
	entries map[string]*secret.Secret
	moved   [][2]string // (from, to) pairs from Move calls
	removed []string
	set     map[string]string // name → password from Set calls
}

func newMockStore(entries map[string]string) *mockStore {
	ms := &mockStore{
		entries: make(map[string]*secret.Secret),
		set:     make(map[string]string),
	}
	for k, v := range entries {
		ms.entries[k] = secret.New(v, "")
	}
	return ms
}

func (m *mockStore) List(_ string) ([]string, error) {
	names := make([]string, 0, len(m.entries))
	for k := range m.entries {
		names = append(names, k)
	}
	return names, nil
}

func (m *mockStore) Get(name string) (*secret.Secret, error) {
	sec, ok := m.entries[name]
	if !ok {
		return nil, fmt.Errorf("store: entry not found: %s", name)
	}
	return sec, nil
}

func (m *mockStore) Set(name string, sec *secret.Secret) error {
	m.set[name] = sec.Password()
	m.entries[name] = sec
	return nil
}

func (m *mockStore) Remove(name string) error {
	delete(m.entries, name)
	m.removed = append(m.removed, name)
	return nil
}

func (m *mockStore) Move(from, to string) error {
	sec, ok := m.entries[from]
	if !ok {
		return fmt.Errorf("store: entry not found: %s", from)
	}
	delete(m.entries, from)
	m.entries[to] = sec
	m.moved = append(m.moved, [2]string{from, to})
	return nil
}

func (m *mockStore) Exists(name string) bool {
	_, ok := m.entries[name]
	return ok
}

func (m *mockStore) Dir() string { return "/tmp/test-store" }

// buildTestModel creates a Model backed by a mockStore with the given entries.
func buildTestModel(entries map[string]string) Model {
	ms := newMockStore(entries)
	cfg := config.Default()
	cfg.NoColor = true
	m, err := NewModel(Options{Store: ms, Cfg: cfg})
	if err != nil {
		panic(err)
	}
	m.SetSize(80, 24)
	return m
}

// --- TASK.md mandated tests ---

func TestOpenEntryWithoutIdentity_GivesError(t *testing.T) {
	// When the store cannot decrypt (Get returns an error), the detail view
	// must show a clear error message, not panic.
	missingStore := &missingIdentityStore{name: "github.com/alice"}
	cfg := config.Default()
	cfg.NoColor = true
	m, err := NewModel(Options{Store: missingStore, Cfg: cfg})
	if err != nil {
		t.Fatal(err)
	}
	m.SetSize(80, 24)

	// Open the entry.
	m.openEntry("github.com/alice")
	// Simulate the async unlock result with an error.
	updated, _ := m.Update(unlockResult{sec: nil, err: fmt.Errorf("no identity found")})
	m2 := updated.(Model)

	view := m2.View()
	if !strings.Contains(view, "error") {
		t.Errorf("detail view should show error, got:\n%s", view)
	}
	if m2.unlockErr == nil {
		t.Error("unlockErr should be set")
	}
}

// missingIdentityStore returns a name in List but fails on Get.
type missingIdentityStore struct{ name string }

func (s *missingIdentityStore) List(_ string) ([]string, error) { return []string{s.name}, nil }
func (s *missingIdentityStore) Get(string) (*secret.Secret, error) {
	return nil, fmt.Errorf("age: no identity matched any recipient")
}
func (s *missingIdentityStore) Set(string, *secret.Secret) error { return nil }
func (s *missingIdentityStore) Remove(string) error              { return nil }
func (s *missingIdentityStore) Move(string, string) error        { return nil }
func (s *missingIdentityStore) Exists(string) bool               { return true }
func (s *missingIdentityStore) Dir() string                      { return "/tmp/test-store" }

func TestPasswordMaskedByDefault(t *testing.T) {
	m := buildTestModel(map[string]string{
		"secret/entry": "hunter2",
	})

	// Open an entry and deliver the decrypted secret.
	m.openEntry("secret/entry")
	m.sec = secret.New("hunter2", "username: alice")

	view := m.View()
	// Should contain mask, not the actual password.
	if strings.Contains(view, "hunter2") {
		t.Errorf("detail view should mask password, got:\n%s", view)
	}
	if !strings.Contains(view, "••••••••") {
		t.Errorf("detail view should show mask, got:\n%s", view)
	}

	// Toggle password.
	m.showPass = true
	view = m.View()
	if !strings.Contains(view, "hunter2") {
		t.Errorf("detail view with showPass should reveal password, got:\n%s", view)
	}
}

func TestOTPTimerMatchesPkgOTP(t *testing.T) {
	uri := "otpauth://totp/Test:alice?secret=JBSWY3DPEHPK3PXP&issuer=Test&period=30"
	cfg, err := parseOTP(uri)
	if err != nil {
		t.Fatal(err)
	}
	m := Model{otpCfg: cfg}
	m.updateOTP()

	// Cross-check with pkg/otp directly.
	now := time.Now()
	wantCode, err := cfg.Code(now)
	if err != nil {
		t.Fatal(err)
	}
	if m.otpCode != wantCode {
		t.Errorf("TUI OTP code = %q, pkg/otp code = %q", m.otpCode, wantCode)
	}

	// Check remaining seconds is consistent with Expires.
	wantExpires := cfg.Expires(now)
	wantRemain := int(time.Until(wantExpires).Seconds())
	if wantRemain < 0 {
		wantRemain = 0
	}
	// Allow 1s tolerance since time advances between calls.
	diff := m.otpRemain - wantRemain
	if diff < -1 || diff > 1 {
		t.Errorf("TUI OTP remain = %d, pkg/otp remain = %d", m.otpRemain, wantRemain)
	}
}

func TestNavigation2000Entries_NoDecrypt(t *testing.T) {
	// Build a store with 2000 entries. The tree should build and render
	// without calling Get on any of them.
	entries := make(map[string]string, 2000)
	for i := 0; i < 2000; i++ {
		name := fmt.Sprintf("dir%d/entry%d", i/100, i)
		entries[name] = fmt.Sprintf("pass%d", i)
	}

	m := buildTestModel(entries)

	// Navigate down 10 times — should not trigger decryption.
	for i := 0; i < 10; i++ {
		updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
		m = updated.(Model)
	}

	// The secret should still be nil — no decryption happened.
	if m.sec != nil {
		t.Error("navigating the tree should not decrypt entries")
	}
	if m.view != viewTree {
		t.Errorf("view = %d, want viewTree", m.view)
	}
}

// --- Unit tests ---

func TestModelViewTreeRenders(t *testing.T) {
	m := buildTestModel(map[string]string{
		"github.com/alice": "pw1",
		"github.com/bob":   "pw2",
		"bank/tinkoff":     "pw3",
		"root":             "pw4",
	})

	view := m.View()
	if view == "" {
		t.Fatal("View() returned empty string")
	}
	if !strings.Contains(view, "github.com") {
		t.Errorf("tree view should contain 'github.com', got:\n%s", view)
	}
}

func TestModelNavigateDown(t *testing.T) {
	m := buildTestModel(map[string]string{
		"github.com/alice": "pw1",
		"root":             "pw2",
	})

	if m.cursor != 0 {
		t.Fatalf("initial cursor = %d, want 0", m.cursor)
	}

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	m2 := updated.(Model)
	if m2.cursor != 1 {
		t.Errorf("cursor after 'j' = %d, want 1", m2.cursor)
	}
}

func TestModelNavigateUp(t *testing.T) {
	m := buildTestModel(map[string]string{
		"alpha": "pw1",
		"bravo": "pw2",
	})
	m.cursor = 1

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'k'}})
	m2 := updated.(Model)
	if m2.cursor != 0 {
		t.Errorf("cursor after 'k' = %d, want 0", m2.cursor)
	}
}

func TestModelSearchTransition(t *testing.T) {
	m := buildTestModel(map[string]string{
		"github.com/alice": "pw1",
	})

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	m2 := updated.(Model)
	if m2.view != viewSearch {
		t.Errorf("view after '/' = %d, want viewSearch", m2.view)
	}
}

func TestModelQuit(t *testing.T) {
	m := buildTestModel(map[string]string{
		"root": "pw1",
	})

	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if cmd == nil {
		t.Error("expected a quit command from 'q'")
	}
}

func TestMaskPassword(t *testing.T) {
	got := maskPassword("hunter2")
	want := "••••••••"
	if got != want {
		t.Errorf("maskPassword = %q, want %q", got, want)
	}
	got = maskPassword("")
	if got != want {
		t.Errorf("maskPassword(empty) = %q, want %q", got, want)
	}
}

func TestScrollWindow(t *testing.T) {
	tests := []struct {
		cursor, total, h   int
		wantStart, wantEnd int
	}{
		{0, 10, 5, 0, 5},
		{9, 10, 5, 5, 10},
		{2, 10, 5, 0, 5},
		{4, 10, 5, 2, 7},
		{0, 3, 10, 0, 3},
	}
	for _, tt := range tests {
		start, end := scrollWindow(tt.cursor, tt.total, tt.h)
		if start != tt.wantStart || end != tt.wantEnd {
			t.Errorf("scrollWindow(%d, %d, %d) = (%d, %d), want (%d, %d)",
				tt.cursor, tt.total, tt.h, start, end, tt.wantStart, tt.wantEnd)
		}
	}
}

func TestModelLockedView(t *testing.T) {
	cfg := config.Default()
	cfg.NoColor = true
	m := Model{
		cfg:    cfg,
		km:     defaultKeymap(),
		st:     newStyles(true),
		view:   viewLocked,
		locked: true,
	}
	m.SetSize(80, 24)

	view := m.View()
	if !strings.Contains(view, "locked") {
		t.Errorf("locked view should mention 'locked', got:\n%s", view)
	}
}

func TestModelAutolock(t *testing.T) {
	cfg := config.Default()
	cfg.NoColor = true
	m := Model{
		cfg:          cfg,
		km:           defaultKeymap(),
		st:           newStyles(true),
		view:         viewTree,
		lastActivity: time.Now().Add(-6 * time.Minute),
		sec:          secret.New("password", ""),
	}
	m.SetSize(80, 24)

	updated, _ := m.Update(tickMsg(time.Now()))
	m2 := updated.(Model)
	if !m2.locked {
		t.Error("expected model to be locked after 5 min idle")
	}
	if m2.sec != nil {
		t.Error("expected secret to be cleared on lock")
	}
}

func TestModelUnlockFromLocked(t *testing.T) {
	cfg := config.Default()
	cfg.NoColor = true
	m := Model{
		cfg:          cfg,
		km:           defaultKeymap(),
		st:           newStyles(true),
		view:         viewLocked,
		locked:       true,
		lastActivity: time.Now(),
	}
	m.SetSize(80, 24)

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	m2 := updated.(Model)
	if m2.locked {
		t.Error("any key should unlock from locked state")
	}
	if m2.view != viewTree {
		t.Error("unlocked should return to tree view")
	}
}

func TestModelDelete(t *testing.T) {
	ms := newMockStore(map[string]string{
		"entry1": "pw1",
		"entry2": "pw2",
	})
	cfg := config.Default()
	cfg.NoColor = true
	m, _ := NewModel(Options{Store: ms, Cfg: cfg})
	m.SetSize(80, 24)

	// Open entry1, trigger delete confirm, confirm.
	m.openEntry("entry1")
	m.sec = secret.New("pw1", "")
	m.confirmAction = "delete"
	m.confirmTarget = "entry1"
	m.confirmFocus = 0 // yes
	m.view = viewConfirm

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e' /* enter is special, simulate via string */}})
	_ = updated.(Model)

	// Simulate enter key.
	m2 := Model(m)
	m2.confirmFocus = 0
	m2.confirmAction = "delete"
	m2.confirmTarget = "entry1"
	m2.store = ms
	updated2, _ := m2.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m3 := updated2.(Model)

	if !strings.Contains(m3.status, "deleted") {
		t.Errorf("expected delete success in status, got: %q", m3.status)
	}
	if len(ms.removed) != 1 || ms.removed[0] != "entry1" {
		t.Errorf("expected entry1 to be removed, got: %v", ms.removed)
	}
}

func TestModelRename(t *testing.T) {
	ms := newMockStore(map[string]string{
		"old-name": "pw1",
	})
	cfg := config.Default()
	cfg.NoColor = true
	m, _ := NewModel(Options{Store: ms, Cfg: cfg})
	m.SetSize(80, 24)

	// Enter rename view.
	m.renameFrom = "old-name"
	m.renameTo = "old-name" // start with same name
	m.view = viewRename

	// Type new name: clear, then "new-name" one char at a time.
	m.renameTo = ""
	for _, ch := range "new-name" {
		updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{ch}})
		m = updated.(Model)
	}

	// Confirm rename.
	updated2, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m3 := updated2.(Model)

	if len(ms.moved) != 1 || ms.moved[0] != [2]string{"old-name", "new-name"} {
		t.Errorf("expected move old-name→new-name, got: %v", ms.moved)
	}
	if !strings.Contains(m3.status, "renamed") {
		t.Errorf("expected rename success in status, got: %q", m3.status)
	}
}

func TestModelRenameEmpty(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw1"})
	m.renameFrom = "entry"
	m.renameTo = ""
	m.view = viewRename

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m2 := updated.(Model)

	if !strings.Contains(m2.status, "cannot be empty") {
		t.Errorf("expected empty name error, got: %q", m2.status)
	}
	if m2.view != viewRename {
		t.Error("should stay in rename view on error")
	}
}

func TestModelSearchFilter(t *testing.T) {
	m := buildTestModel(map[string]string{
		"github.com/alice": "pw1",
		"github.com/bob":   "pw2",
		"bank/tinkoff":     "pw3",
	})
	m.view = viewSearch
	m.query = ""

	// Type "alice" letter by letter.
	for _, ch := range "alice" {
		updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{ch}})
		m = updated.(Model)
	}

	if len(m.filtered) != 1 {
		t.Fatalf("expected 1 match for 'alice', got %d: %v", len(m.filtered), m.filtered)
	}
	if m.filtered[0] != "github.com/alice" {
		t.Errorf("filtered[0] = %q, want %q", m.filtered[0], "github.com/alice")
	}
}

func TestModelSearchEscape(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.view = viewSearch

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m2 := updated.(Model)
	if m2.view != viewTree {
		t.Error("esc should return to tree view")
	}
}

func TestStatusMsgUpdatesStatusBar(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})

	updated, _ := m.Update(statusMsg("test message"))
	m2 := updated.(Model)
	if m2.status != "test message" {
		t.Errorf("status = %q, want %q", m2.status, "test message")
	}
}

func TestModelGenerateView(t *testing.T) {
	m := buildTestModel(map[string]string{
		"entry": "oldpw",
	})
	m.openEntry("entry")
	m.sec = secret.New("oldpw", "username: alice")
	m.genTarget = "entry"
	m.genLength = 16
	m.genPreview = "newgeneratedpw"
	m.view = viewGenerate

	view := m.View()
	if !strings.Contains(view, "generate") {
		t.Errorf("generate view should show header, got:\n%s", view)
	}
	if !strings.Contains(view, "newgeneratedpw") {
		t.Errorf("generate view should show preview, got:\n%s", view)
	}
}

func TestModelHistoryView(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.histTarget = "entry"
	m.histList = []vcs.Commit{
		{Hash: "abc1234", Author: "Alice", Date: time.Now(), Subject: "Add given password for entry"},
		{Hash: "def5678", Author: "Bob", Date: time.Now().Add(-24 * time.Hour), Subject: "Edit password for entry"},
	}
	m.histCur = 0
	m.view = viewHistory

	view := m.View()
	if !strings.Contains(view, "history") {
		t.Errorf("history view should show header, got:\n%s", view)
	}
	if !strings.Contains(view, "abc1234") {
		t.Errorf("history view should show commit hash, got:\n%s", view)
	}
}

func TestModelHistoryEmpty(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.histTarget = "entry"
	m.histList = nil
	m.view = viewHistory

	view := m.View()
	if !strings.Contains(view, "no git history") {
		t.Errorf("empty history should show message, got:\n%s", view)
	}
}

func TestModelHistoryError(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.histTarget = "entry"
	m.histErr = fmt.Errorf("not a git repo")
	m.view = viewHistory

	view := m.View()
	if !strings.Contains(view, "error") {
		t.Errorf("history error should be shown, got:\n%s", view)
	}
}

func TestModelHistoryNavigation(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.histTarget = "entry"
	m.histList = []vcs.Commit{
		{Hash: "abc1234", Author: "Alice", Date: time.Now(), Subject: "first"},
		{Hash: "def5678", Author: "Bob", Date: time.Now(), Subject: "second"},
	}
	m.histCur = 0
	m.view = viewHistory

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	m2 := updated.(Model)
	if m2.histCur != 1 {
		t.Errorf("histCur after 'j' = %d, want 1", m2.histCur)
	}

	updated2, _ := m2.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'k'}})
	m3 := updated2.(Model)
	if m3.histCur != 0 {
		t.Errorf("histCur after 'k' = %d, want 0", m3.histCur)
	}
}

func TestModelHistoryBack(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.view = viewHistory

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m2 := updated.(Model)
	if m2.view != viewDetail {
		t.Error("esc from history should go to detail view")
	}
}

func TestModelHistoryResult(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.histTarget = "entry"
	m.view = viewHistory

	commits := []vcs.Commit{
		{Hash: "abc1234", Author: "Alice", Date: time.Now(), Subject: "first"},
	}
	updated, _ := m.Update(historyResult{commits: commits})
	m2 := updated.(Model)
	if len(m2.histList) != 1 {
		t.Errorf("histList len = %d, want 1", len(m2.histList))
	}
	if m2.histList[0].Hash != "abc1234" {
		t.Errorf("histList[0].Hash = %q, want %q", m2.histList[0].Hash, "abc1234")
	}
}

func TestModelPageDown(t *testing.T) {
	// Build a model with 50 entries.
	entries := make(map[string]string, 50)
	for i := 0; i < 50; i++ {
		entries[fmt.Sprintf("entry%d", i)] = fmt.Sprintf("pw%d", i)
	}
	m := buildTestModel(entries)
	if m.cursor != 0 {
		t.Fatalf("initial cursor = %d, want 0", m.cursor)
	}

	// PgDn.
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyPgDown})
	m2 := updated.(Model)
	if m2.cursor <= 0 {
		t.Errorf("cursor after pgdown = %d, want > 0", m2.cursor)
	}
}

func TestModelMouseScroll(t *testing.T) {
	entries := make(map[string]string, 20)
	for i := 0; i < 20; i++ {
		entries[fmt.Sprintf("entry%d", i)] = fmt.Sprintf("pw%d", i)
	}
	m := buildTestModel(entries)
	if m.cursor != 0 {
		t.Fatalf("initial cursor = %d, want 0", m.cursor)
	}

	// Mouse wheel down.
	updated, _ := m.Update(tea.MouseMsg{Action: tea.MouseActionPress, Button: tea.MouseButtonWheelDown})
	m2 := updated.(Model)
	if m2.cursor <= 0 {
		t.Errorf("cursor after wheel down = %d, want > 0", m2.cursor)
	}
}

func TestTruncate(t *testing.T) {
	// ASCII.
	if got := truncate("hello world", 5); got != "hello" {
		t.Errorf("truncate(ascii, 5) = %q, want %q", got, "hello")
	}
	// Short string stays.
	if got := truncate("hi", 10); got != "hi" {
		t.Errorf("truncate(short) = %q, want %q", got, "hi")
	}
	// CJK (each char is 2 cells).
	if got := truncate("你好世界", 4); got != "你好" {
		t.Errorf("truncate(cjk, 4) = %q, want %q", got, "你好")
	}
}

// --- Detail view coverage ---

func TestDetailEscBack(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.openEntry("entry")
	m.sec = secret.New("pw", "")

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m2 := updated.(Model)
	if m2.view != viewTree {
		t.Error("esc from detail should return to tree")
	}
	if m2.sec != nil {
		t.Error("secret should be cleared on close")
	}
}

func TestDetailTogglePassword(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.openEntry("entry")
	m.sec = secret.New("hunter2", "")

	view := m.View()
	if strings.Contains(view, "hunter2") {
		t.Error("password should be masked by default")
	}

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'p'}})
	m2 := updated.(Model)
	if !m2.showPass {
		t.Error("p should toggle showPass")
	}
	view2 := m2.View()
	if !strings.Contains(view2, "hunter2") {
		t.Error("password should be visible after toggle")
	}
}

func TestDetailDeleteFlow(t *testing.T) {
	ms := newMockStore(map[string]string{"entry": "pw", "other": "pw2"})
	cfg := config.Default()
	cfg.NoColor = true
	m, _ := NewModel(Options{Store: ms, Cfg: cfg})
	m.SetSize(80, 24)
	m.openEntry("entry")
	m.sec = secret.New("pw", "")

	// Press 'd' — should go to confirm.
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	m2 := updated.(Model)
	if m2.view != viewConfirm {
		t.Errorf("after 'd' view = %d, want viewConfirm", m2.view)
	}
	if m2.confirmAction != "delete" {
		t.Errorf("confirmAction = %q, want %q", m2.confirmAction, "delete")
	}

	// Move to "Yes" and confirm.
	m2.confirmFocus = 0
	updated2, _ := m2.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m3 := updated2.(Model)
	if !strings.Contains(m3.status, "deleted") {
		t.Errorf("expected delete success, got: %q", m3.status)
	}
}

func TestDetailCopyPassword(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.openEntry("entry")
	m.sec = secret.New("pw", "")

	// 'c' with nil clipBackend should produce statusMsg.
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'c'}})
	_ = updated.(Model)
	if cmd == nil {
		t.Error("expected a command from 'c'")
	}
}

func TestDetailCopyOTP(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.openEntry("entry")
	m.sec = secret.New("pw", "")
	m.otpCode = "123456"

	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'o'}})
	_ = updated.(Model)
	if cmd == nil {
		t.Error("expected a command from 'o'")
	}
}

func TestDetailRenameTransition(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.openEntry("entry")
	m.sec = secret.New("pw", "")

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	m2 := updated.(Model)
	if m2.view != viewRename {
		t.Error("'r' should go to rename view")
	}
	if m2.renameFrom != "entry" {
		t.Errorf("renameFrom = %q, want %q", m2.renameFrom, "entry")
	}
}

func TestDetailGenerateTransition(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.openEntry("entry")
	m.sec = secret.New("pw", "")

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'g'}})
	m2 := updated.(Model)
	if m2.view != viewGenerate {
		t.Error("'g' should go to generate view")
	}
}

func TestDetailHistoryTransition(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.openEntry("entry")
	m.sec = secret.New("pw", "")

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	m2 := updated.(Model)
	if m2.view != viewHistory {
		t.Error("'y' should go to history view")
	}
}

func TestDetailDecryptingView(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.openEntry("entry")
	// sec is nil → "decrypting..." view.

	view := m.View()
	if !strings.Contains(view, "decrypting") {
		t.Errorf("should show 'decrypting' when sec is nil, got:\n%s", view)
	}
}

func TestDetailErrorView(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.openEntry("entry")
	m.unlockErr = fmt.Errorf("no identity")

	view := m.View()
	if !strings.Contains(view, "error") {
		t.Errorf("should show error, got:\n%s", view)
	}
}

func TestDetailFieldsAndOTP(t *testing.T) {
	sec := secret.New("hunter2", "username: alice\nurl: https://github.com\notpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&period=30")
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.openEntry("entry")
	m.sec = sec
	m.showPass = false
	m.initOTP()

	view := m.View()
	if !strings.Contains(view, "alice") {
		t.Errorf("should show field value, got:\n%s", view)
	}
	if !strings.Contains(view, "OTP") {
		t.Errorf("should show OTP section, got:\n%s", view)
	}
}

// --- Search view coverage ---

func TestViewSearchRendering(t *testing.T) {
	m := buildTestModel(map[string]string{
		"github.com/alice": "pw1",
		"bank/tinkoff":     "pw2",
	})
	m.view = viewSearch
	m.query = "git"
	m.filtered = []string{"github.com/alice"}
	m.srchCur = 0

	view := m.View()
	if !strings.Contains(view, "search") {
		t.Errorf("search view should show search header, got:\n%s", view)
	}
	if !strings.Contains(view, "github.com/alice") {
		t.Errorf("search view should show filtered results, got:\n%s", view)
	}
}

func TestViewSearchNoMatches(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.view = viewSearch
	m.query = "zzz"
	m.filtered = nil

	view := m.View()
	if !strings.Contains(view, "no matches") {
		t.Errorf("search with no results should say 'no matches', got:\n%s", view)
	}
}

func TestSearchBackspace(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.view = viewSearch
	m.query = "ab"

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{8}}) // ctrl+h = backspace
	m2 := updated.(Model)
	if m2.query != "a" {
		t.Errorf("after backspace query = %q, want %q", m2.query, "a")
	}
}

// --- Confirm view coverage ---

func TestViewConfirmRendering(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.view = viewConfirm
	m.confirmAction = "delete"
	m.confirmTarget = "entry"
	m.confirmFocus = 1 // "No" selected

	view := m.View()
	if !strings.Contains(view, "delete") {
		t.Errorf("confirm view should show action, got:\n%s", view)
	}
	if !strings.Contains(view, "entry") {
		t.Errorf("confirm view should show target, got:\n%s", view)
	}
}

func TestConfirmCancel(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.confirmAction = "delete"
	m.confirmTarget = "entry"
	m.confirmFocus = 1
	m.view = viewConfirm

	// ConfirmFocus = 1 (No) + enter = cancel.
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m2 := updated.(Model)
	if m2.view != viewTree {
		t.Error("enter on 'No' should return to tree")
	}
}

func TestConfirmEsc(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.view = viewConfirm

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m2 := updated.(Model)
	if m2.view != viewDetail {
		t.Error("esc from confirm should return to detail")
	}
}

// --- Rename view coverage ---

func TestViewRenameRendering(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.renameFrom = "entry"
	m.renameTo = "new-entry"
	m.view = viewRename

	view := m.View()
	if !strings.Contains(view, "rename") {
		t.Errorf("rename view should show header, got:\n%s", view)
	}
	if !strings.Contains(view, "new-entry") {
		t.Errorf("rename view should show target name, got:\n%s", view)
	}
}

func TestRenameBackspace(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.renameFrom = "entry"
	m.renameTo = "abc"
	m.view = viewRename

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyBackspace})
	m2 := updated.(Model)
	if m2.renameTo != "ab" {
		t.Errorf("after backspace renameTo = %q, want %q", m2.renameTo, "ab")
	}
}

func TestRenameCtrlU(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.renameFrom = "entry"
	m.renameTo = "something"
	m.view = viewRename

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlU})
	m2 := updated.(Model)
	if m2.renameTo != "" {
		t.Errorf("ctrl+u should clear renameTo, got %q", m2.renameTo)
	}
}

func TestRenameSameName(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.renameFrom = "entry"
	m.renameTo = "entry" // same
	m.view = viewRename

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m2 := updated.(Model)
	if m2.view != viewDetail {
		t.Error("same name should return to detail without calling Move")
	}
}

// --- Generate view coverage ---

func TestViewGenerateRendering(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.genTarget = "entry"
	m.genLength = 16
	m.genPreview = "xK9mP2qR"
	m.view = viewGenerate

	view := m.View()
	if !strings.Contains(view, "xK9mP2qR") {
		t.Errorf("generate view should show preview, got:\n%s", view)
	}
}

func TestViewGenerateNoPreview(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.genTarget = "entry"
	m.genPreview = ""
	m.view = viewGenerate

	view := m.View()
	if !strings.Contains(view, "generating") {
		t.Errorf("generate with no preview should show 'generating', got:\n%s", view)
	}
}

func TestGenerateApply(t *testing.T) {
	ms := newMockStore(map[string]string{"entry": "oldpw"})
	cfg := config.Default()
	cfg.NoColor = true
	m, _ := NewModel(Options{Store: ms, Cfg: cfg})
	m.SetSize(80, 24)

	m.openEntry("entry")
	m.sec = secret.New("oldpw", "username: alice")
	m.genTarget = "entry"
	m.genPreview = "newpw123"
	m.view = viewGenerate

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m2 := updated.(Model)
	if !strings.Contains(m2.status, "generated") {
		t.Errorf("expected generate success, got: %q", m2.status)
	}
	if ms.set["entry"] != "newpw123" {
		t.Errorf("store.Set was not called with new password, got: %q", ms.set["entry"])
	}
}

func TestGenerateRegenerate(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.genTarget = "entry"
	m.genPreview = "old-preview"
	m.view = viewGenerate

	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	m2 := updated.(Model)
	_ = m2
	if cmd == nil {
		t.Error("'r' should trigger regenerate command")
	}
}

func TestGenerateCancel(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.sec = secret.New("pw", "")
	m.genTarget = "entry"
	m.view = viewGenerate

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m2 := updated.(Model)
	if m2.view != viewDetail {
		t.Error("esc from generate should return to detail")
	}
}

// --- OTP init and update ---

func TestInitOTPWithEntry(t *testing.T) {
	sec := secret.New("pw", "otpauth://totp/Test:alice?secret=JBSWY3DPEHPK3PXP&issuer=Test&period=30")
	m := Model{sec: sec}
	m.initOTP()
	if m.otpCfg == nil {
		t.Fatal("initOTP should set otpCfg when entry has otpauth URI")
	}
	if m.otpCode == "" {
		t.Error("initOTP should set otpCode via updateOTP")
	}
}

func TestInitOTPNoEntry(t *testing.T) {
	m := Model{sec: secret.New("pw", "username: alice")}
	m.initOTP()
	if m.otpCfg != nil {
		t.Error("initOTP should not set otpCfg when no otpauth URI")
	}
}

func TestInitOTPBadURI(t *testing.T) {
	sec := secret.New("pw", "otpauth://invalid-no-secret")
	m := Model{sec: sec}
	m.initOTP()
	if m.otpCfg != nil {
		t.Error("initOTP should ignore bad otpauth URI")
	}
}

func TestUpdateOTPHOTP(t *testing.T) {
	// HOTP should not be updated by timer (no countdown).
	uri := "otpauth://hotp/Test:alice?secret=JBSWY3DPEHPK3PXP&issuer=Test&counter=0"
	cfg, err := otp.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	m := Model{otpCfg: cfg}
	m.updateOTP()
	if m.otpCode != "" {
		t.Error("HOTP should not auto-generate codes via updateOTP")
	}
}

// --- Clipboard ---

func TestCopyPasswordCmdNoBackend(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.sec = secret.New("pw", "")
	m.clipBackend = nil

	cmd := m.copyPasswordCmd()
	result := cmd()
	msg, ok := result.(statusMsg)
	if !ok {
		t.Fatal("expected statusMsg from copyPasswordCmd")
	}
	if !strings.Contains(string(msg), "no clipboard") {
		t.Errorf("expected no clipboard message, got: %q", msg)
	}
}

func TestCopyOTPCmdNoBackend(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.otpCode = "123456"
	m.clipBackend = nil

	cmd := m.copyOTPCodeCmd()
	result := cmd()
	msg, ok := result.(statusMsg)
	if !ok {
		t.Fatal("expected statusMsg from copyOTPCodeCmd")
	}
	if !strings.Contains(string(msg), "no clipboard") {
		t.Errorf("expected no clipboard message, got: %q", msg)
	}
}

// --- Copy in detail with no sec ---

func TestDetailCopyNoSecret(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.openEntry("entry")
	// sec is nil.

	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'c'}})
	m2 := updated.(Model)
	if cmd != nil {
		t.Error("c with nil sec should not produce a command")
	}
	_ = m2
}

func TestDetailCopyOTPNoCode(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.openEntry("entry")
	m.sec = secret.New("pw", "")
	m.otpCode = ""

	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'o'}})
	_ = updated.(Model)
	if cmd != nil {
		t.Error("o with no otpCode should not produce a command")
	}
}

// --- Mouse scroll in search/history ---

func TestMouseScrollSearch(t *testing.T) {
	m := buildTestModel(map[string]string{
		"entry1": "pw1",
		"entry2": "pw2",
		"entry3": "pw3",
		"entry4": "pw4",
	})
	m.view = viewSearch
	m.filtered = []string{"entry1", "entry2", "entry3", "entry4"}
	m.srchCur = 0

	updated, _ := m.Update(tea.MouseMsg{Action: tea.MouseActionPress, Button: tea.MouseButtonWheelDown})
	m2 := updated.(Model)
	if m2.srchCur <= 0 {
		t.Errorf("wheel down in search should advance srchCur, got %d", m2.srchCur)
	}
}

func TestMouseScrollHistory(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.view = viewHistory
	m.histList = []vcs.Commit{
		{Hash: "a1", Subject: "first"},
		{Hash: "a2", Subject: "second"},
		{Hash: "a3", Subject: "third"},
	}
	m.histCur = 1

	updated, _ := m.Update(tea.MouseMsg{Action: tea.MouseActionPress, Button: tea.MouseButtonWheelUp})
	m2 := updated.(Model)
	if m2.histCur != 0 {
		t.Errorf("wheel up in history should move histCur, got %d", m2.histCur)
	}
}

// --- Insert view coverage ---

func TestInsertFromTree(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	m2 := updated.(Model)
	if m2.view != viewInsert {
		t.Errorf("n from tree should go to insert, got view=%d", m2.view)
	}
	if m2.insertStep != 0 {
		t.Errorf("insertStep = %d, want 0", m2.insertStep)
	}
}

func TestInsertNameInput(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.view = viewInsert
	m.insertStep = 0

	// Type "bank/card".
	for _, ch := range "bank" {
		updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{ch}})
		m = updated.(Model)
	}
	if m.insertName != "bank" {
		t.Errorf("insertName after typing = %q, want %q", m.insertName, "bank")
	}

	// Type "/" as part of path.
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	m = updated.(Model)
	if m.insertName != "bank/" {
		t.Errorf("insertName after slash = %q, want %q", m.insertName, "bank/")
	}
}

func TestInsertBackspace(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.view = viewInsert
	m.insertStep = 0
	m.insertName = "abc"

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyBackspace})
	m2 := updated.(Model)
	if m2.insertName != "ab" {
		t.Errorf("backspace: insertName = %q, want %q", m2.insertName, "ab")
	}
}

func TestInsertCtrlU(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.view = viewInsert
	m.insertStep = 0
	m.insertName = "something"

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlU})
	m2 := updated.(Model)
	if m2.insertName != "" {
		t.Errorf("ctrl+u should clear insertName, got %q", m2.insertName)
	}
}

func TestInsertEmptyNameRejected(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.view = viewInsert
	m.insertStep = 0
	m.insertName = ""

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m2 := updated.(Model)
	if m2.insertStep != 0 {
		t.Error("empty name should not advance to step 1")
	}
	if !strings.Contains(m2.status, "empty") {
		t.Errorf("expected empty-name error, got: %q", m2.status)
	}
}

func TestInsertDuplicateRejected(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.view = viewInsert
	m.insertStep = 0
	m.insertName = "entry" // already exists

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m2 := updated.(Model)
	if m2.insertStep != 0 {
		t.Error("duplicate name should not advance to step 1")
	}
	if !strings.Contains(m2.status, "already exists") {
		t.Errorf("expected duplicate error, got: %q", m2.status)
	}
}

func TestInsertEnterAdvancesToStep1(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.view = viewInsert
	m.insertStep = 0
	m.insertName = "new/entry"

	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m2 := updated.(Model)
	if m2.insertStep != 1 {
		t.Errorf("enter with valid name should go to step 1, got %d", m2.insertStep)
	}
	if cmd == nil {
		t.Error("enter should trigger password generation command")
	}
}

func TestInsertGenerateResult(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.view = viewInsert
	m.insertStep = 1
	m.insertName = "new/entry"

	updated, _ := m.Update(generateResult{password: "genPw123"})
	m2 := updated.(Model)
	if m2.insertPassword != "genPw123" {
		t.Errorf("insertPassword = %q, want %q", m2.insertPassword, "genPw123")
	}
}

func TestInsertPreviewApply(t *testing.T) {
	ms := newMockStore(map[string]string{"existing": "pw1"})
	cfg := config.Default()
	cfg.NoColor = true
	m, _ := NewModel(Options{Store: ms, Cfg: cfg})
	m.SetSize(80, 24)

	m.view = viewInsert
	m.insertStep = 1
	m.insertName = "new/entry"
	m.insertPassword = "genPw123"

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m2 := updated.(Model)
	if m2.view != viewTree {
		t.Errorf("after apply should return to tree, got view=%d", m2.view)
	}
	if !strings.Contains(m2.status, "created") {
		t.Errorf("expected 'created' status, got: %q", m2.status)
	}
	if ms.set["new/entry"] != "genPw123" {
		t.Errorf("store.Set was not called, got: %q", ms.set["new/entry"])
	}
}

func TestInsertPreviewRegenerate(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.view = viewInsert
	m.insertStep = 1
	m.insertName = "new/entry"
	m.insertPassword = "old-pw"

	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	_ = updated.(Model)
	if cmd == nil {
		t.Error("r should trigger regenerate command")
	}
}

func TestInsertPreviewBack(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.view = viewInsert
	m.insertStep = 1
	m.insertName = "new/entry"

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m2 := updated.(Model)
	if m2.insertStep != 0 {
		t.Errorf("esc from preview should go back to name input, got step=%d", m2.insertStep)
	}
}

func TestInsertNameViewRendering(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.view = viewInsert
	m.insertStep = 0
	m.insertName = "bank"

	view := m.View()
	if !strings.Contains(view, "new entry") {
		t.Errorf("insert step 0 should show header, got:\n%s", view)
	}
	if !strings.Contains(view, "bank") {
		t.Errorf("insert step 0 should show typed name, got:\n%s", view)
	}
}

func TestInsertPreviewViewRendering(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.view = viewInsert
	m.insertStep = 1
	m.insertName = "bank"
	m.insertPassword = "xK9mP2qR"

	view := m.View()
	if !strings.Contains(view, "xK9mP2qR") {
		t.Errorf("insert preview should show password, got:\n%s", view)
	}
}

// --- Lifecycle: Init, unlockCmd, generateCmd, tickCmd ---

func TestInitReturnsCmd(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	cmd := m.Init()
	if cmd == nil {
		t.Error("Init should return a non-nil Cmd")
	}
}

func TestUnlockCmdSuccess(t *testing.T) {
	ms := newMockStore(map[string]string{"entry": "secret-pw"})
	m := buildMockModel(ms)
	cmd := m.unlockCmd("entry")
	msg := cmd()
	res, ok := msg.(unlockResult)
	if !ok {
		t.Fatalf("unlockCmd should return unlockResult, got %T", msg)
	}
	if res.err != nil {
		t.Errorf("unexpected error: %v", res.err)
	}
	if res.sec.Password() != "secret-pw" {
		t.Errorf("password = %q, want %q", res.sec.Password(), "secret-pw")
	}
}

func TestUnlockCmdError(t *testing.T) {
	ms := newMockStore(map[string]string{})
	m := buildMockModel(ms)
	cmd := m.unlockCmd("nonexistent")
	msg := cmd()
	res, ok := msg.(unlockResult)
	if !ok {
		t.Fatalf("unlockCmd should return unlockResult, got %T", msg)
	}
	if res.err == nil {
		t.Error("expected error for nonexistent entry")
	}
}

func TestGenerateCmdSuccess(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	cmd := m.generateCmd(16)
	msg := cmd()
	res, ok := msg.(generateResult)
	if !ok {
		t.Fatalf("generateCmd should return generateResult, got %T", msg)
	}
	if res.err != nil {
		t.Errorf("unexpected error: %v", res.err)
	}
	if len(res.password) != 16 {
		t.Errorf("generated password length = %d, want 16", len(res.password))
	}
}

func TestTickCmd(t *testing.T) {
	cmd := tickCmd()
	if cmd == nil {
		t.Error("tickCmd should return a non-nil Cmd")
	}
	msg := cmd()
	if _, ok := msg.(tickMsg); !ok {
		t.Fatalf("tickCmd should return tickMsg, got %T", msg)
	}
}

func TestSplitFieldCoverage(t *testing.T) {
	tests := []struct {
		line    string
		wantKey string
		wantVal string
		wantOk  bool
	}{
		{"username: alice", "username", "alice", true},
		{"no colon here", "", "", false},
		{"  url : https://example.com  ", "url", "https://example.com", true},
	}
	for _, tt := range tests {
		k, v, ok := splitField(tt.line)
		if k != tt.wantKey || v != tt.wantVal || ok != tt.wantOk {
			t.Errorf("splitField(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tt.line, k, v, ok, tt.wantKey, tt.wantVal, tt.wantOk)
		}
	}
}

// buildMockModel creates a Model with the given mockStore and default config.
func buildMockModel(ms *mockStore) Model {
	cfg := config.Default()
	cfg.NoColor = true
	m, _ := NewModel(Options{Store: ms, Cfg: cfg})
	m.SetSize(80, 24)
	return m
}

// --- Expand/collapse all ---

func TestExpandAll(t *testing.T) {
	m := buildTestModel(map[string]string{
		"bank/tinkoff": "pw1",
		"bank/alfa":    "pw2",
		"email/gmail":  "pw3",
	})
	// Collapse everything first.
	collapseAll(m.tree)
	m.flat = flatten(m.tree)

	// All dirs collapsed: only "bank" and "email" visible (plus maybe root entries).
	initialCount := len(m.flat)

	// Shift+E = expand all.
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'E'}})
	m2 := updated.(Model)
	if len(m2.flat) <= initialCount {
		t.Errorf("expand all should increase visible items: was %d, got %d", initialCount, len(m2.flat))
	}
}

func TestCollapseAll(t *testing.T) {
	m := buildTestModel(map[string]string{
		"bank/tinkoff": "pw1",
		"bank/alfa":    "pw2",
		"email/gmail":  "pw3",
	})
	// Everything expanded by default from buildTree.
	initialCount := len(m.flat)

	// Shift+C = collapse all.
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'C'}})
	m2 := updated.(Model)
	if len(m2.flat) >= initialCount {
		t.Errorf("collapse all should decrease visible items: was %d, got %d", initialCount, len(m2.flat))
	}
	if m2.cursor != 0 {
		t.Errorf("collapse all should reset cursor to 0, got %d", m2.cursor)
	}
}

// --- Tree expand/collapse helpers ---

func TestExpandCollapseAllDirect(t *testing.T) {
	root := buildTree([]string{"a/b/c", "a/b/d", "x/y"})
	expandAll(root)
	// Find dir "a" and check expanded.
	a := findChild(root, "a")
	if a == nil || !a.expanded {
		t.Error("expandAll should set dir 'a' to expanded")
	}
	b := findChild(a, "b")
	if b == nil || !b.expanded {
		t.Error("expandAll should set dir 'b' to expanded")
	}

	collapseAll(root)
	if a.expanded || b.expanded {
		t.Error("collapseAll should set all dirs to collapsed")
	}
}

func TestWalkDirs(t *testing.T) {
	root := buildTree([]string{"a/b/c", "x/y"})
	var visited []string
	walkDirs(root, func(n *treeNode) {
		visited = append(visited, n.name)
	})
	for _, want := range []string{"a", "b", "x"} {
		found := false
		for _, v := range visited {
			if v == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("walkDirs should visit %q, got %v", want, visited)
		}
	}
}

// findChild returns the first child of parent with the given name, or nil.
func findChild(parent *treeNode, name string) *treeNode {
	for _, c := range parent.children {
		if c.name == name {
			return c
		}
	}
	return nil
}
