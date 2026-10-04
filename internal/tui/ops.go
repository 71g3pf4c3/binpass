package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// startDup opens the duplicate (cp) flow for the given entry, proposing a
// copy name the way a file manager would.
func (m *Model) startDup() {
	m.dupFrom = m.current
	m.dupTo = proposeCopyName(m.current, func(n string) bool { return m.store.Exists(n) })
	m.view = viewDup
}

// proposeCopyName derives "<base> (copy)" and keeps appending " (copy)"
// until the name is free — the least surprising default for a duplicate.
func proposeCopyName(name string, exists func(string) bool) string {
	candidate := name + " (copy)"
	for exists(candidate) {
		candidate = candidate + " (copy)"
	}
	return candidate
}

// handleDup dispatches keys for the duplicate-name input.
func (m Model) handleDup(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		if m.dupTo == "" {
			m.status = "copy: name cannot be empty"
			return m, nil
		}
		if m.dupTo == m.dupFrom {
			m.status = "copy: name must differ from the original"
			return m, nil
		}
		if m.store.Exists(m.dupTo) {
			m.confirmAction = "dup-overwrite"
			m.confirmTarget = m.dupTo
			m.confirmFocus = 1 // overwriting is destructive; default to "no".
			m.view = viewConfirm
			return m, nil
		}
		m.dupApply()

	case m.km.Back:
		m.view = viewDetail
		return m, nil

	default:
		applyInputKey(&m.dupTo, msg)
	}
	return m, nil
}

// dupApply performs the copy through store.Copy — the same path `cp`
// takes — and returns to the original entry.
func (m *Model) dupApply() {
	if err := m.store.Copy(m.dupFrom, m.dupTo); err != nil {
		m.status = "copy: " + err.Error()
		return
	}
	m.status = "copied to " + m.dupTo
	m.rebuildTree()
	m.view = viewDetail
}

// viewDup renders the duplicate-name input.
func (m Model) viewDup() string {
	var b strings.Builder
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "  %s %s\n", m.st.header.Render("copy:"), m.st.bold.Render(m.dupFrom))
	fmt.Fprintf(&b, "  %s %s\n", m.st.dimmed.Render("to:"), m.st.visible.Render(m.dupTo)+"▏")
	fmt.Fprintf(&b, "\n  %s\n", m.st.dimmed.Render("enter:copy  esc:cancel"))
	return b.String()
}
