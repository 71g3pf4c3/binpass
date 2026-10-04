package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/71g3pf4c3/binpass/pkg/clip"
	"github.com/71g3pf4c3/binpass/pkg/typer"
	tea "github.com/charmbracelet/bubbletea"
)

// typeSettle is the pause before typed keystrokes land: the TUI's own
// terminal has focus when the key is pressed, and the user needs a beat
// to switch to the window that actually should receive the password.
var typeSettle = 3 * time.Second

// clipCopy and typeText are thin seams over pkg/clip and pkg/typer: the
// real functions drive external tools (wl-clipboard, xdotool, …) that a
// test must neither run nor need. Everything else in the copy/type flows
// is plain logic and tested directly.
var (
	clipCopy = clip.CopyWithTimeout
	typeText = typer.Type
)

// startFieldPick opens the copy-a-field picker for the open entry.
func (m *Model) startFieldPick() {
	m.fieldCur = 0
	m.view = viewFieldPick
}

// fieldRows returns the copyable values of the open entry: the password,
// every named field, and the OTP code when one is live.
func (m Model) fieldRows() []fieldRow {
	rows := []fieldRow{{label: "password", value: m.sec.Password()}}
	for _, f := range m.sec.Fields() {
		rows = append(rows, fieldRow{label: f.Key, value: f.Value})
	}
	if m.otpCode != "" {
		rows = append(rows, fieldRow{label: "otp", value: m.otpCode})
	}
	return rows
}

// fieldRow is one copyable line of the field picker.
type fieldRow struct {
	label string
	value string
}

// handleFieldPick dispatches keys for the field picker.
func (m Model) handleFieldPick(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	rows := m.fieldRows()
	switch msg.String() {
	case m.km.Back:
		m.view = viewDetail
		return m, nil

	case "up", "k":
		if m.fieldCur > 0 {
			m.fieldCur--
		}
	case "down", "j":
		if m.fieldCur < len(rows)-1 {
			m.fieldCur++
		}

	case m.km.Enter:
		if m.fieldCur < len(rows) {
			cmd := m.copyValueCmd(rows[m.fieldCur].label, rows[m.fieldCur].value)
			m.view = viewDetail
			return m, cmd
		}
	}
	return m, nil
}

// viewFieldPick renders the field picker.
func (m Model) viewFieldPick() string {
	var b strings.Builder
	fmt.Fprintf(&b, "  %s %s\n\n", m.st.header.Render("copy field:"), m.st.bold.Render(m.current))
	for i, r := range m.fieldRows() {
		line := truncate(fmt.Sprintf("  %s  %s", m.st.dimmed.Render(r.label+":"), r.value), m.width)
		if i == m.fieldCur {
			fmt.Fprintf(&b, "%s\n", m.st.selected.Render(line))
		} else {
			fmt.Fprintf(&b, "%s\n", line)
		}
	}
	bar := m.statusBar("enter:copy  j/k:nav  esc:back")
	return b.String() + bar
}

// copyValueCmd returns a tea.Cmd that copies an arbitrary value — the
// password, a named field or an OTP code — through the same clipboard
// path (with restore-on-timeout) the password copy uses.
func (m Model) copyValueCmd(label, value string) tea.Cmd {
	cb := m.clipBackend
	dur := m.cfg.ClipTime
	return func() tea.Msg {
		if cb == nil {
			return statusMsg("no clipboard backend")
		}
		ctx, cancel := context.WithTimeout(context.Background(), dur+time.Second)
		defer cancel()
		if err := clipCopy(ctx, cb, value, dur); err != nil {
			return statusMsg("clipboard: " + err.Error())
		}
		return statusMsg("copied " + label + " to clipboard")
	}
}

// typeValueCmd returns a tea.Cmd that types a value into the focused
// window through pkg/typer (stdin of the typing tool, never argv), after
// a settle delay during which the user switches focus.
func (m Model) typeValueCmd(label, value string) tea.Cmd {
	return func() tea.Msg {
		time.Sleep(typeSettle)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := typeText(ctx, value); err != nil {
			return statusMsg("type: " + err.Error())
		}
		return statusMsg("typed " + label + " into the focused window")
	}
}
