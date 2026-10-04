package tui

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/71g3pf4c3/binpass/pkg/store"
	tea "github.com/charmbracelet/bubbletea"
)

// grepResult carries the outcome of a content search. grep decrypts the
// whole store, exactly like the CLI command, so it runs once on enter —
// never per keystroke.
type grepResult struct {
	matches []store.Match
	err     error
}

// handleGrep dispatches keys for the content-search view.
func (m Model) handleGrep(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.grepDone {
		return m.handleGrepResults(msg)
	}
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit

	case m.km.Back:
		m.view = viewTree
		m.grepDone = false
		return m, nil

	case "enter":
		if m.grepQuery == "" {
			return m, nil
		}
		return m, m.grepCmd(m.grepQuery)

	case "ctrl+u":
		m.grepQuery = ""

	case "backspace", "ctrl+h":
		r := []rune(m.grepQuery)
		if len(r) > 0 {
			m.grepQuery = string(r[:len(r)-1])
		}

	default:
		runes := []rune(msg.String())
		if len(runes) == 1 && isPrintable(runes[0]) {
			m.grepQuery += string(runes[0])
		}
	}
	return m, nil
}

// handleGrepResults dispatches keys while search results are displayed.
func (m Model) handleGrepResults(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit

	case m.km.Back:
		m.view = viewTree
		m.grepDone = false
		return m, nil

	case "up", "k":
		if m.grepCur > 0 {
			m.grepCur--
		}
	case "down", "j":
		if m.grepCur < len(m.grepMatches)-1 {
			m.grepCur++
		}

	case "left", "h": // refine the query
		m.grepDone = false
		m.grepMatches = nil
		m.grepCur = 0

	case m.km.Enter, "l", "right":
		if m.grepCur < len(m.grepMatches) {
			name := m.grepMatches[m.grepCur].Name
			m.openEntry(name)
			m.grepDone = false
			return m, m.unlockCmd(name)
		}
	}
	return m, nil
}

// viewGrep renders the content search: the pattern input, or the matches.
func (m Model) viewGrep() string {
	var b strings.Builder
	if !m.grepDone {
		fmt.Fprintf(&b, "  %s %s\n\n", m.st.search.Render("grep"), m.st.bold.Render(m.grepQuery))
		fmt.Fprintln(&b, m.st.dimmed.Render("  decrypts the whole store — enter to run, esc to cancel"))
		bar := m.statusBar("enter:search  esc:cancel")
		return b.String() + bar
	}

	fmt.Fprintf(&b, "  %s %s\n\n", m.st.search.Render("grep"), m.st.bold.Render(m.grepQuery))
	if m.grepErr != nil {
		fmt.Fprintf(&b, "  %s %s\n", m.st.errorMsg.Render("error:"), m.grepErr)
		bar := m.statusBar("esc:back")
		return b.String() + bar
	}
	if len(m.grepMatches) == 0 {
		fmt.Fprintln(&b, m.st.dimmed.Render("  no matches"))
		bar := m.statusBar("h:refine  esc:back")
		return b.String() + bar
	}

	avail := m.height - 5
	if avail < 1 {
		avail = 1
	}
	start, end := scrollWindow(m.grepCur, len(m.grepMatches), avail)
	for i := start; i < end; i++ {
		match := m.grepMatches[i]
		line := truncate(fmt.Sprintf("  %s  (%d line%s)", match.Name, len(match.Lines), plural(len(match.Lines))), m.width)
		if i == m.grepCur {
			fmt.Fprintf(&b, "%s\n", m.st.selected.Render(line))
		} else {
			fmt.Fprintf(&b, "%s\n", line)
		}
		// First matching line as a preview, indented under the entry.
		if len(match.Lines) > 0 {
			preview := truncate("      "+strings.TrimSpace(match.Lines[0]), m.width)
			if i == m.grepCur {
				fmt.Fprintf(&b, "%s\n", m.st.selected.Render(preview))
			} else {
				fmt.Fprintf(&b, "%s\n", m.st.dimmed.Render(preview))
			}
		}
	}

	bar := m.statusBar("enter:open  h:refine  j/k:nav  esc:back")
	return b.String() + bar
}

// grepCmd returns a command that greps the decrypted store contents with
// the pattern, mirroring the CLI's regexp semantics.
func (m Model) grepCmd(pattern string) tea.Cmd {
	s := m.store
	return func() tea.Msg {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return grepResult{err: err}
		}
		matches, err := s.Grep("", re.MatchString)
		return grepResult{matches: matches, err: err}
	}
}

// plural returns "" for one, "s" otherwise.
func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
