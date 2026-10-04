package tui

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/71g3pf4c3/binpass/pkg/clip"
	"github.com/71g3pf4c3/binpass/pkg/secret"
	tea "github.com/charmbracelet/bubbletea"
)

// fakeClip records clipboard writes without touching any real selection.
type fakeClip struct {
	copied string
}

func (f *fakeClip) Name() string                              { return "fake" }
func (f *fakeClip) Copy(_ context.Context, text string) error { f.copied = text; return nil }
func (f *fakeClip) Paste(_ context.Context) (string, error)   { return "", nil }
func (f *fakeClip) Available() bool                           { return true }

// withClip swaps the model's clipboard backend for the test.
func withClip(m *Model, f *fakeClip) { m.clipBackend = f }

// --- field picker ---

func TestFieldRowsIncludeFieldsAndOTP(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.openEntry("entry")
	m.sec = secret.New("hunter2", "username: alice\nurl: https://ex.io")
	m.otpCode = "123456"

	rows := m.fieldRows()
	want := []struct{ label, value string }{
		{"password", "hunter2"},
		{"username", "alice"},
		{"url", "https://ex.io"},
		{"otp", "123456"},
	}
	if len(rows) != len(want) {
		t.Fatalf("fieldRows = %+v", rows)
	}
	for i, w := range want {
		if rows[i].label != w.label || rows[i].value != w.value {
			t.Errorf("row %d = %+v, want %s:%s", i, rows[i], w.label, w.value)
		}
	}
}

func TestFieldPickFlowCopiesSelectedField(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.openEntry("entry")
	m.sec = secret.New("hunter2", "username: alice\nurl: https://ex.io")

	// 'C' opens the picker.
	m = press(m, key('C'))
	if m.view != viewFieldPick {
		t.Fatalf("C must open the field picker, got view %d", m.view)
	}
	view := m.View()
	if !strings.Contains(view, "username") || !strings.Contains(view, "url") {
		t.Errorf("picker should list the fields, got:\n%s", view)
	}

	// Select username (second row), copy through the seam — the real
	// CopyWithTimeout sleeps for ClipTime to restore the clipboard, which
	// no test should sit through.
	fc := &fakeClip{}
	withClip(&m, fc)
	oldCopy := clipCopy
	clipCopy = func(_ context.Context, _ clip.Backend, text string, _ time.Duration) error {
		fc.copied = text
		return nil
	}
	defer func() { clipCopy = oldCopy }()

	m = press(m, key('j'))
	m = press(m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.view != viewDetail {
		t.Errorf("after copy view = %d, want detail", m.view)
	}
	msg := m.copyValueCmd("username", "alice")()
	if s := msg.(statusMsg); !strings.Contains(string(s), "username") { //nolint:forcetypeassert // shape is fixed.
		t.Errorf("status = %q", s)
	}
	if fc.copied != "alice" {
		t.Errorf("clipboard got %q, want alice", fc.copied)
	}
}

func TestFieldPickEscape(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.openEntry("entry")
	m.sec = secret.New("pw", "username: alice")
	m.startFieldPick()
	m = press(m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.view != viewDetail {
		t.Error("esc from the field picker must return to detail")
	}
}

// --- type into the focused window ---

func TestTypePasswordUsesTyperSeam(t *testing.T) {
	// The settle delay exists so the user can switch focus; a test must
	// not sit through it.
	oldSettle, oldType := typeSettle, typeText
	typeSettle = 0
	defer func() { typeSettle, typeText = oldSettle, oldType }()

	var typed string
	typeText = func(_ context.Context, text string) error {
		typed = text
		return nil
	}

	m := buildTestModel(map[string]string{"entry": "pw"})
	m.openEntry("entry")
	m.sec = secret.New("hunter2", "")

	updated, cmd := m.Update(key('t'))
	m = updated.(Model)
	if cmd == nil {
		t.Fatal("'t' must produce a typing command")
	}
	msg := cmd()
	if s := msg.(statusMsg); !strings.Contains(string(s), "typed") { //nolint:forcetypeassert // shape is fixed.
		t.Errorf("status = %q", s)
	}
	if typed != "hunter2" {
		t.Errorf("typer received %q, want hunter2", typed)
	}
	if m.view != viewDetail {
		t.Errorf("typing must not change the view, got %d", m.view)
	}
}

func TestTypePasswordNoToolAvailable(t *testing.T) {
	oldSettle, oldType := typeSettle, typeText
	typeSettle = 0
	defer func() { typeSettle, typeText = oldSettle, oldType }()
	typeText = func(_ context.Context, _ string) error {
		return context.DeadlineExceeded
	}

	m := buildTestModel(map[string]string{"entry": "pw"})
	m.openEntry("entry")
	m.sec = secret.New("hunter2", "")

	_, cmd := m.Update(key('t'))
	msg := cmd()
	if s := msg.(statusMsg); !strings.Contains(string(s), "type:") { //nolint:forcetypeassert // shape is fixed.
		t.Errorf("a failing typer must surface its error, got %q", s)
	}
}

// --- generate settings ---

func TestGenerateSettingsAdjustLengthAndSymbols(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.openEntry("entry")
	m.sec = secret.New("oldpw", "")
	m.genTarget = "entry"
	m.genLength = 16
	m.genSymbols = true
	m.view = viewGenerate

	m = press(m, key('+'))
	if m.genLength != 17 {
		t.Errorf("after + length = %d, want 17", m.genLength)
	}
	m = press(m, key('-'))
	m = press(m, key('-'))
	if m.genLength != 15 {
		t.Errorf("after two - length = %d, want 15", m.genLength)
	}
	m = press(m, key('s'))
	if m.genSymbols {
		t.Error("'s' must toggle the symbol alphabet off")
	}
	view := m.View()
	if !strings.Contains(view, "no symbols") {
		t.Errorf("generate view should show the alphabet, got:\n%s", view)
	}

	// Bounds: never below the floor, never above the ceiling.
	m.genLength = pwgenMaxLen
	m = press(m, key('+'))
	if m.genLength != pwgenMaxLen {
		t.Errorf("length above ceiling = %d", m.genLength)
	}
	m.genLength = pwgenMinLen
	m = press(m, key('-'))
	if m.genLength != pwgenMinLen {
		t.Errorf("length below floor = %d", m.genLength)
	}
}

func TestInsertGenerateSettings(t *testing.T) {
	m, _ := insertAtStep1(t, "bank/card")
	m.insertLen = 16
	m.insertSymbols = true

	m = press(m, key('+'))
	if m.insertLen != 17 {
		t.Errorf("after + length = %d, want 17", m.insertLen)
	}
	m = press(m, key('s'))
	if m.insertSymbols {
		t.Error("'s' must toggle the insert alphabet")
	}
	view := m.View()
	if !strings.Contains(view, "no symbols") {
		t.Errorf("insert view should show the alphabet, got:\n%s", view)
	}
}

// --- status view ---

func TestStatusViewRoutingAndRendering(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})

	updated, cmd := m.Update(key('S'))
	m = updated.(Model)
	if m.view != viewStatus {
		t.Fatalf("S must open the status view, got %d", m.view)
	}
	if cmd == nil {
		t.Error("S must start status collection")
	}
	if !strings.Contains(m.View(), "gathering") {
		t.Errorf("status view should show a loading state, got:\n%s", m.View())
	}

	// Deliver a result: git present with two dirty files, sync never ran.
	updated2, _ := m.Update(statusResult{
		gitStatus: []string{" M entry.age", "?? new.age"},
		gitHead:   "abc1234 last commit",
	})
	m = updated2.(Model)
	view := m.View()
	for _, want := range []string{"abc1234 last commit", "2 uncommitted", " M entry.age", "sync:", "never"} {
		if !strings.Contains(view, want) {
			t.Errorf("status view missing %q, got:\n%s", want, view)
		}
	}

	// A git error renders as "not a repository", not a crash.
	updated, _ = m.Update(statusResult{gitErr: context.DeadlineExceeded})
	m = updated.(Model)
	if !strings.Contains(m.View(), "not a git repository") {
		t.Errorf("git error should render as not-a-repo, got:\n%s", m.View())
	}

	// esc returns to the tree.
	m = press(m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.view != viewTree {
		t.Error("esc from status must return to the tree")
	}
}

func TestStatusCmdRealGitRepo(t *testing.T) {
	// A real git repository exercises the actual git plumbing; the sync
	// state goes to an isolated BINPASS_STATE_DIR.
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not found on PATH")
	}
	dir := t.TempDir()
	ms := newMockStore(map[string]string{"entry": "pw"})
	ms.dir = dir // Dir() is where statusCmd points git at.
	for _, args := range [][]string{
		{"init", "-q", dir},
		{"-C", dir, "config", "user.email", "t@example.invalid"},
		{"-C", dir, "config", "user.name", "t"},
		{"-C", dir, "commit", "--allow-empty", "-m", "init"},
	} {
		if out, err := exec.Command("git", args...).CombinedOutput(); err != nil { //nolint:gosec // fixed test arguments.
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	t.Setenv("BINPASS_STATE_DIR", t.TempDir())

	m, err := NewModel(Options{Store: ms, Cfg: testConfig()})
	if err != nil {
		t.Fatal(err)
	}
	res, ok := m.statusCmd()().(statusResult) //nolint:forcetypeassert // shape is fixed.
	if !ok {
		t.Fatal("statusCmd must return a statusResult")
	}
	if res.gitErr != nil {
		t.Fatalf("git status failed: %v", res.gitErr)
	}
	if len(res.gitStatus) != 0 {
		t.Errorf("clean tree should have no changes, got %v", res.gitStatus)
	}
	if !strings.Contains(res.gitHead, "init") {
		t.Errorf("gitHead = %q", res.gitHead)
	}
	if res.syncErr != nil {
		t.Errorf("fresh state dir should open cleanly: %v", res.syncErr)
	}
	if !res.lastSync.IsZero() {
		t.Errorf("lastSync = %v, want zero", res.lastSync)
	}
}

func TestCopyValueCmdNoBackend(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.clipBackend = nil
	msg := m.copyValueCmd("x", "y")()
	if s := msg.(statusMsg); !strings.Contains(string(s), "no clipboard") { //nolint:forcetypeassert // shape is fixed.
		t.Errorf("status = %q, want no-clipboard error", s)
	}
}

func TestCopyValueCmdRestoreTimeout(t *testing.T) {
	// The copy must go through clip.CopyWithTimeout's restore contract:
	// the value is cleared again after the configured duration. The
	// seam records that CopyWithTimeout was the function invoked.
	old := clipCopy
	defer func() { clipCopy = old }()

	var gotDur time.Duration
	clipCopy = func(ctx context.Context, _ clip.Backend, _ string, d time.Duration) error {
		gotDur = d
		if _, ok := ctx.Deadline(); !ok {
			t.Error("copy must run under a deadline")
		}
		return nil
	}

	m := buildTestModel(map[string]string{"entry": "pw"})
	fc := &fakeClip{}
	m.clipBackend = fc
	msg := m.copyValueCmd("username", "alice")()
	if s := msg.(statusMsg); !strings.Contains(string(s), "username") { //nolint:forcetypeassert // shape is fixed.
		t.Errorf("status = %q", s)
	}
	if gotDur != m.cfg.ClipTime {
		t.Errorf("restore timeout = %v, want %v", gotDur, m.cfg.ClipTime)
	}
}
