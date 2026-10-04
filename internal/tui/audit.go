package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/71g3pf4c3/binpass/pkg/audit"
	tea "github.com/charmbracelet/bubbletea"
)

// auditResult carries the collected audit report.
type auditResult struct {
	report *audit.Report
	err    error
}

// auditHIBP builds the breach-database client for the audit. It is a
// seam: the real client carries the on-disk cache (so consecutive audits
// over an unchanged store stay offline), while tests inject a no-op to
// keep the network out of them.
var auditHIBP = func() audit.HIBPChecker {
	c := audit.NewHIBPClient()
	if dir, err := os.UserCacheDir(); err == nil {
		c.CacheDir = filepath.Join(dir, "binpass", "hibp")
	}
	return c
}

// handleAudit dispatches keys for the audit report view.
func (m Model) handleAudit(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case m.km.Back, "q":
		m.view = viewTree
		return m, nil

	case "up", "k":
		if m.auditCur > 0 {
			m.auditCur--
		}
	case "down", "j":
		if m.auditCur < len(m.auditRows())-1 {
			m.auditCur++
		}

	case m.km.Enter, "l", "right":
		rows := m.auditRows()
		if m.auditCur < len(rows) {
			name := rows[m.auditCur].name
			m.openEntry(name)
			return m, m.unlockCmd(name)
		}
	}
	return m, nil
}

// auditRow is one navigable line of the report: an entry with findings.
type auditRow struct {
	name     string
	severity audit.Severity
	details  []string
}

// severityRank orders severities critical > warning > info; the empty
// severity (no findings) sorts last.
func severityRank(s audit.Severity) int {
	switch s {
	case audit.Critical:
		return 0
	case audit.Warning:
		return 1
	case audit.Info:
		return 2
	}
	return 3
}

// auditRows flattens the report into display rows, keeping the report's
// ordering and reducing an entry to its worst severity.
func (m Model) auditRows() []auditRow {
	if m.auditRep == nil {
		return nil
	}
	rows := make([]auditRow, 0, len(m.auditRep.Entries))
	for _, e := range m.auditRep.Entries {
		if len(e.Findings) == 0 {
			continue
		}
		sev := audit.Severity("")
		for _, f := range e.Findings {
			if sev == "" || severityRank(f.Severity) < severityRank(sev) {
				sev = f.Severity
			}
		}
		var details []string
		for _, f := range e.Findings {
			details = append(details, f.Detail)
		}
		rows = append(rows, auditRow{name: e.Name, severity: sev, details: details})
	}
	return rows
}

// viewAudit renders the audit report.
func (m Model) viewAudit() string {
	var b strings.Builder
	fmt.Fprintf(&b, "  %s\n\n", m.st.header.Render("audit"))

	if m.auditRep == nil && m.auditErr == nil {
		fmt.Fprintln(&b, m.st.dimmed.Render("  auditing (decrypts the whole store)..."))
		bar := m.statusBar("esc:back")
		return b.String() + bar
	}
	if m.auditErr != nil {
		fmt.Fprintf(&b, "  %s %s\n", m.st.errorMsg.Render("error:"), m.auditErr)
		bar := m.statusBar("esc:back")
		return b.String() + bar
	}

	st := m.auditRep.Stats
	fmt.Fprintf(&b, "  %s %d audited, %d critical, %d warning, %d info, %d clean\n\n",
		m.st.dimmed.Render("stats:"),
		st.Audited, st.Critical, st.Warning, st.Info, st.Clean)

	rows := m.auditRows()
	if len(rows) == 0 {
		fmt.Fprintln(&b, m.st.dimmed.Render("  no findings"))
		bar := m.statusBar("esc:back")
		return b.String() + bar
	}

	avail := m.height - 6
	if avail < 1 {
		avail = 1
	}
	start, end := scrollWindow(m.auditCur, len(rows), avail)
	for i := start; i < end; i++ {
		r := rows[i]
		line := truncate(fmt.Sprintf("  %-8s %s", string(r.severity), r.name), m.width)
		if i == m.auditCur {
			fmt.Fprintf(&b, "%s\n", m.st.selected.Render(line))
		} else if r.severity == audit.Critical {
			fmt.Fprintf(&b, "%s\n", m.st.errorMsg.Render(line))
		} else {
			fmt.Fprintf(&b, "%s\n", m.st.dimmed.Render(line))
		}
		// First finding as an indented preview.
		if len(r.details) > 0 {
			preview := truncate("           "+r.details[0], m.width)
			if i == m.auditCur {
				fmt.Fprintf(&b, "%s\n", m.st.selected.Render(preview))
			} else {
				fmt.Fprintf(&b, "%s\n", m.st.dimmed.Render(preview))
			}
		}
	}

	bar := m.statusBar("enter:open  j/k:nav  esc:back")
	return b.String() + bar
}

// auditCmd returns a command that runs the full store audit through
// pkg/audit — the same engine the `audit` command drives. The audit
// decrypts the whole store and may hit HIBP per uncached prefix, so it
// runs under a generous timeout off the UI loop.
func (m Model) auditCmd() tea.Cmd {
	s := m.store
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		a := &audit.Auditor{
			Store:      s,
			Opts:       audit.DefaultOptions(),
			HIBPClient: auditHIBP(),
		}
		rep, err := a.Run(ctx)
		return auditResult{report: rep, err: err}
	}
}
