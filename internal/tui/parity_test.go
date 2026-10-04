package tui

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/71g3pf4c3/binpass/pkg/audit"
	"github.com/71g3pf4c3/binpass/pkg/clip"
	"github.com/71g3pf4c3/binpass/pkg/otp"
	"github.com/71g3pf4c3/binpass/pkg/secret"
	tea "github.com/charmbracelet/bubbletea"
)

const hotpURI = "otpauth://hotp/Test:alice?secret=JBSWY3DPEHPK3PXP&counter=0"

// --- HOTP reveal and counter advancement ---

func TestAdvanceCounterRewritesURIOnly(t *testing.T) {
	sec := secret.New("pw", "username: alice\n"+hotpURI+"\nnote")
	updated, err := advanceCounter(sec, hotpURI, 3)
	if err != nil {
		t.Fatal(err)
	}
	got := updated.String()
	if !strings.Contains(got, "counter=3") || strings.Contains(got, "counter=0") {
		t.Errorf("counter not advanced in place: %q", got)
	}
	if !strings.Contains(got, "username: alice") || !strings.Contains(got, "note") {
		t.Errorf("unrelated lines must be untouched: %q", got)
	}
}

func TestHOTPRevealAdvancesAndCopies(t *testing.T) {
	ms := newMockStore(map[string]string{"entry": "pw"})
	ms.entries["entry"] = secret.New("pw", hotpURI)
	m, err := NewModel(Options{Store: ms, Cfg: testConfig()})
	if err != nil {
		t.Fatal(err)
	}
	m.SetSize(80, 24)
	m.openEntry("entry")

	// The reference code for counter 0, computed by pkg/otp itself.
	cfg, err := otp.Parse(hotpURI)
	if err != nil {
		t.Fatal(err)
	}
	wantCode, err := cfg.Code(time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// Deliver the async unlock, then press 'o'. The clipboard goes
	// through the seam so the test neither runs a real tool nor waits
	// out the restore timeout.
	var clipped string
	oldCopy := clipCopy
	clipCopy = func(_ context.Context, _ clip.Backend, text string, _ time.Duration) error {
		clipped = text
		return nil
	}
	defer func() { clipCopy = oldCopy }()

	updated, _ := m.Update(unlockResult{sec: ms.entries["entry"]})
	m = updated.(Model)
	if m.otpCfg == nil || m.otpCfg.Kind != otp.HOTP {
		t.Fatal("HOTP entry must arm otpCfg")
	}
	view := m.View()
	if !strings.Contains(view, "HOTP") {
		t.Errorf("detail view must label HOTP, got:\n%s", view)
	}

	updated, cmd := m.Update(key('o'))
	m = updated.(Model)
	if cmd == nil {
		t.Fatal("'o' on an HOTP entry must produce a reveal command")
	}
	msg := cmd()
	res, ok := msg.(hotpResult)
	if !ok || res.err != nil {
		t.Fatalf("hotpRevealCmd = %+v", msg)
	}
	if res.code != wantCode {
		t.Errorf("code = %q, want %q", res.code, wantCode)
	}
	if clipped != wantCode {
		t.Errorf("clipboard got %q, want %q", clipped, wantCode)
	}

	// The counter must now be 1 on disk.
	stored := ms.entries["entry"].String()
	if !strings.Contains(stored, "counter=1") {
		t.Errorf("stored entry must carry counter=1: %q", stored)
	}

	// Feeding the result back re-arms the model from the stored secret.
	updated, _ = m.Update(res)
	m = updated.(Model)
	if m.otpCfg == nil {
		t.Fatal("otpCfg must be re-armed after the reveal")
	}
	uri, _ := m.sec.OTP()
	if !strings.Contains(uri, "counter=1") {
		t.Errorf("re-armed URI = %q", uri)
	}
}

// --- duplicate (cp) ---

func TestDuplicateFlow(t *testing.T) {
	ms := newMockStore(map[string]string{"entry": "pw"})
	ms.entries["entry"] = secret.New("pw", "username: alice\n")
	m, _ := NewModel(Options{Store: ms, Cfg: testConfig()})
	m.SetSize(80, 24)
	m.openEntry("entry")
	m.sec = secret.New("pw", "username: alice")

	m = press(m, key('Y'))
	if m.view != viewDup {
		t.Fatalf("Y must open the duplicate view, got %d", m.view)
	}
	if m.dupTo != "entry (copy)" {
		t.Errorf("proposed name = %q, want entry (copy)", m.dupTo)
	}
	m = press(m, tea.KeyMsg{Type: tea.KeyEnter})
	if _, ok := ms.entries["entry (copy)"]; !ok {
		t.Fatal("store.Copy was not performed")
	}
	if got := ms.entries["entry (copy)"].String(); got != "pw\nusername: alice\n" {
		t.Errorf("copy content = %q", got)
	}
	if m.view != viewDetail {
		t.Errorf("after copy view = %d, want detail", m.view)
	}
}

func TestDuplicateOverwriteAsksConfirm(t *testing.T) {
	ms := newMockStore(map[string]string{"entry": "pw", "entry (copy)": "other"})
	m, _ := NewModel(Options{Store: ms, Cfg: testConfig()})
	m.SetSize(80, 24)
	m.openEntry("entry")
	m.sec = secret.New("pw", "")
	m.startDup()
	// "entry (copy)" is taken, so the proposal is "entry (copy) (copy)";
	// replace it with the taken name to force the overwrite gate.
	m.dupTo = "entry (copy)"

	m = press(m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.view != viewConfirm || m.confirmAction != "dup-overwrite" {
		t.Fatalf("overwrite must confirm, view=%d action=%q", m.view, m.confirmAction)
	}
	// Decline: back at the name input, target untouched.
	m = press(m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.view != viewDup {
		t.Fatalf("decline must return to the name input, got %d", m.view)
	}
	if got := ms.entries["entry (copy)"].Password(); got != "other" {
		t.Errorf("declined overwrite must keep the target, got %q", got)
	}
}

func TestDuplicateSameNameRejected(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.openEntry("entry")
	m.sec = secret.New("pw", "")
	m.startDup()
	m.dupTo = "entry"

	m = press(m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.view != viewDup {
		t.Error("copy onto itself must be refused in place")
	}
	if !strings.Contains(m.status, "differ") {
		t.Errorf("status = %q", m.status)
	}
}

// --- tree delete of directories ---

func TestTreeDeleteDirectory(t *testing.T) {
	ms := newMockStore(map[string]string{
		"bank/a": "pw1",
		"bank/b": "pw2",
		"keep":   "pw3",
	})
	m, _ := NewModel(Options{Store: ms, Cfg: testConfig()})
	m.SetSize(80, 24)

	// Put the cursor on the "bank" directory: flatten puts
	// directories first alphabetically; find its row.
	row := -1
	for i, it := range m.flat {
		if !it.node.entry && it.node.name == "bank" {
			row = i
		}
	}
	if row < 0 {
		t.Fatal("bank directory not found in tree")
	}
	m.cursor = row

	m = press(m, key('d'))
	if m.view != viewConfirm || m.confirmAction != "delete-dir" {
		t.Fatalf("d on a directory must confirm delete-dir, view=%d action=%q", m.view, m.confirmAction)
	}
	if !strings.Contains(m.View(), "directory") {
		t.Errorf("confirm must name the directory, got:\n%s", m.View())
	}

	m.confirmFocus = 0
	m = press(m, tea.KeyMsg{Type: tea.KeyEnter})
	if _, ok := ms.entries["bank/a"]; ok {
		t.Error("directory entries must be gone")
	}
	if _, ok := ms.entries["keep"]; !ok {
		t.Error("unrelated entries must survive")
	}
	if m.view != viewTree {
		t.Errorf("after delete view = %d, want tree", m.view)
	}
}

// --- grep across contents ---

func TestGrepFlow(t *testing.T) {
	ms := newMockStore(map[string]string{
		"bank/a": "pw",
		"web/b":  "pw",
	})
	ms.entries["bank/a"] = secret.New("pw", "username: alice\nnote")
	ms.entries["web/b"] = secret.New("pw", "username: bob\nurl: https://ex.io")

	m, _ := NewModel(Options{Store: ms, Cfg: testConfig()})
	m.SetSize(80, 24)

	m = press(m, key('F'))
	if m.view != viewGrep {
		t.Fatalf("F must open grep, got %d", m.view)
	}
	// Empty query must not run.
	m = press(m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.grepDone {
		t.Error("empty pattern must not search")
	}

	for _, r := range "alice" {
		m = press(m, key(r))
	}
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	if cmd == nil {
		t.Fatal("enter must start the search")
	}
	// The command runs outside the model; feed its result back in, the
	// way the bubbletea runtime would.
	updated, _ = m.Update(cmd())
	m = updated.(Model)
	if !m.grepDone || m.grepErr != nil {
		t.Fatalf("grep did not complete: done=%v err=%v", m.grepDone, m.grepErr)
	}
	if len(m.grepMatches) != 1 || m.grepMatches[0].Name != "bank/a" {
		t.Fatalf("matches = %+v", m.grepMatches)
	}
	view := m.View()
	if !strings.Contains(view, "bank/a") || !strings.Contains(view, "alice") {
		t.Errorf("grep view should show entry and preview, got:\n%s", view)
	}

	// Enter opens the matched entry.
	m = press(m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.view != viewDetail || m.current != "bank/a" {
		t.Errorf("enter must open the match, view=%d current=%q", m.view, m.current)
	}
}

func TestGrepInvalidPattern(t *testing.T) {
	m := buildTestModel(map[string]string{"entry": "pw"})
	m.view = viewGrep
	for _, r := range "[unclosed" {
		m = press(m, key(r))
	}
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	if cmd == nil {
		t.Fatal("enter must start the search")
	}
	updated, _ = m.Update(cmd())
	m = updated.(Model)
	if m.grepErr == nil {
		t.Error("invalid regexp must surface its error")
	}
	if !strings.Contains(m.View(), "error") {
		t.Errorf("grep view should show the error, got:\n%s", m.View())
	}
}

// --- audit view ---

func TestAuditViewRenderingAndOpen(t *testing.T) {
	m := buildTestModel(map[string]string{"weak": "pw", "strong": "pw2"})

	m = press(m, key('A'))
	if m.view != viewAudit {
		t.Fatalf("A must open the audit view, got %d", m.view)
	}
	if !strings.Contains(m.View(), "auditing") {
		t.Errorf("audit view should show a loading state, got:\n%s", m.View())
	}

	rep := &audit.Report{
		Stats: audit.Stats{Total: 2, Audited: 2, Critical: 1, Warning: 1},
		Entries: []audit.EntryResult{
			{Name: "weak", Findings: []audit.Finding{
				{Kind: audit.KindLeaked, Severity: audit.Critical, Detail: "password is compromised"},
			}},
			{Name: "strong", Findings: []audit.Finding{
				{Kind: audit.KindWeak, Severity: audit.Warning, Detail: "password is weak"},
			}},
		},
	}
	updated, _ := m.Update(auditResult{report: rep})
	m = updated.(Model)

	view := m.View()
	for _, want := range []string{"2 audited", "1 critical", "weak", "compromised", "strong"} {
		if !strings.Contains(view, want) {
			t.Errorf("audit view missing %q, got:\n%s", want, view)
		}
	}

	// Enter opens the selected finding's entry.
	m = press(m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.view != viewDetail || m.current != "weak" {
		t.Errorf("enter must open the finding's entry, view=%d current=%q", m.view, m.current)
	}
}

func TestAuditCmdRealStore(t *testing.T) {
	// The audit engine is pkg/audit itself; only the HIBP client is
	// stubbed out so the test never touches the network.
	old := auditHIBP
	auditHIBP = func() audit.HIBPChecker {
		return noopHIBP{}
	}
	defer func() { auditHIBP = old }()

	s := newRealStore(t)
	if err := s.Set("weak", secret.New("password", "")); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("fine", secret.New("c9fHb2vQ7x4mL5wZ", "")); err != nil {
		t.Fatal(err)
	}
	m, err := NewModel(Options{Store: s, Cfg: testConfig()})
	if err != nil {
		t.Fatal(err)
	}
	m.SetSize(80, 24)

	msg := m.auditCmd()()
	res, ok := msg.(auditResult)
	if !ok || res.err != nil {
		t.Fatalf("auditCmd = %+v", msg)
	}
	if res.report.Stats.Audited != 2 {
		t.Errorf("audited = %d, want 2", res.report.Stats.Audited)
	}
	var weak bool
	for _, e := range res.report.Entries {
		if e.Name == "weak" && len(e.Findings) > 0 {
			weak = true
		}
	}
	if !weak {
		t.Error("the zxcvbn-weak entry must carry findings")
	}
}

// noopHIBP keeps the audit offline in tests.
type noopHIBP struct{}

func (noopHIBP) Check(_ context.Context, _ string) (bool, error) { return false, nil }
