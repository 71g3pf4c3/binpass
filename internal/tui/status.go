package tui

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/71g3pf4c3/binpass/internal/config"
	"github.com/71g3pf4c3/binpass/pkg/sync"
	tea "github.com/charmbracelet/bubbletea"
)

// statusResult carries the read-only store status: git working-tree state
// and the timestamp of the last sync. Everything here is observation —
// the view never mutates the repository or the sync state.
type statusResult struct {
	gitStatus []string
	gitHead   string
	gitErr    error
	lastSync  time.Time
	syncErr   error
}

// statusCmd collects the store status off the UI loop: git status shells
// out, and the sync StateDB open takes a file lock that a concurrent sync
// process may briefly hold.
func (m Model) statusCmd() tea.Cmd {
	dir := m.store.Dir()
	return func() tea.Msg {
		res := statusResult{}
		// Read-only git plumbing on the store directory; the directory
		// comes from the store itself, not from user input.
		if out, err := exec.Command("git", "-C", dir, "status", "--porcelain").Output(); err != nil { //nolint:gosec // dir is the store root.
			res.gitErr = err
		} else {
			for _, line := range strings.Split(string(out), "\n") {
				if line = strings.TrimSpace(line); line != "" {
					res.gitStatus = append(res.gitStatus, line)
				}
			}
			if head, err := exec.Command("git", "-C", dir, "log", "-1", "--format=%h %s").Output(); err == nil { //nolint:gosec // dir is the store root.
				res.gitHead = strings.TrimSpace(string(head))
			}
		}
		// Opening the sync state read-only in spirit: LastSync is a
		// metadata read, and the DB is closed immediately. A lock
		// held by a running sync shows up as "unavailable", not as a
		// hung TUI.
		if db, err := sync.OpenStateDB(config.StateDir()); err != nil {
			res.syncErr = err
		} else {
			ts, err := db.LastSync()
			if err != nil {
				res.syncErr = err
			} else {
				res.lastSync = ts
			}
			_ = db.Close()
		}
		return res
	}
}

// handleStatus dispatches keys for the status view.
func (m Model) handleStatus(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case m.km.Back, "q", m.km.Quit:
		m.view = viewTree
		return m, nil
	}
	return m, nil
}

// viewStatus renders the read-only store status.
func (m Model) viewStatus() string {
	var b strings.Builder
	fmt.Fprintf(&b, "  %s\n\n", m.st.header.Render("status"))
	fmt.Fprintf(&b, "  %s %s\n", m.st.dimmed.Render("store:"), m.store.Dir())
	fmt.Fprintf(&b, "  %s %d\n", m.st.dimmed.Render("entries:"), len(m.allEntries))
	fmt.Fprintln(&b)

	if m.statRes == nil {
		fmt.Fprintln(&b, m.st.dimmed.Render("  gathering..."))
	} else {
		r := m.statRes
		if r.gitErr != nil {
			fmt.Fprintf(&b, "  %s %s\n", m.st.dimmed.Render("git:"), "not a git repository")
		} else {
			fmt.Fprintf(&b, "  %s %s\n", m.st.dimmed.Render("git:"), r.gitHead)
			if n := len(r.gitStatus); n == 0 {
				fmt.Fprintf(&b, "  %s\n", m.st.dimmed.Render("      working tree clean"))
			} else {
				fmt.Fprintf(&b, "  %s\n", m.st.dimmed.Render(fmt.Sprintf("      %d uncommitted change(s):", n)))
				max := 8
				if len(r.gitStatus) < max {
					max = len(r.gitStatus)
				}
				for _, line := range r.gitStatus[:max] {
					fmt.Fprintf(&b, "  %s\n", m.st.dimmed.Render("      "+truncate(line, m.width-6)))
				}
				if len(r.gitStatus) > max {
					fmt.Fprintf(&b, "  %s\n", m.st.dimmed.Render("      …"))
				}
			}
		}

		switch {
		case m.statRes.syncErr != nil:
			fmt.Fprintf(&b, "  %s %s\n", m.st.dimmed.Render("sync:"), "state unavailable")
		case m.statRes.lastSync.IsZero():
			fmt.Fprintf(&b, "  %s %s\n", m.st.dimmed.Render("sync:"), "never")
		default:
			fmt.Fprintf(&b, "  %s %s\n", m.st.dimmed.Render("sync:"), m.statRes.lastSync.Format("2006-01-02 15:04"))
		}
	}

	bar := m.statusBar("esc:back")
	return b.String() + bar
}
