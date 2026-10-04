package tui

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/71g3pf4c3/binpass/pkg/binary"
	"github.com/71g3pf4c3/binpass/pkg/secret"
	tea "github.com/charmbracelet/bubbletea"
)

// binResult carries the outcome of an asynchronous attach or extract. The
// heavy work (base64 of a whole file, store encryption) runs off the UI
// loop so the TUI stays responsive on large attachments.
type binResult struct {
	desc string
	err  error
}

// --- view: file picker ---

// startFilePicker opens the local-filesystem browser. In dirMode the user
// is choosing an extraction destination; otherwise a file to encrypt into
// the store. The picker only lists directories — it never reads file
// contents, so browsing can not leak data.
func (m *Model) startFilePicker(dirMode bool) {
	m.pickDir = dirMode
	m.filesQuery = ""
	m.filesCur = 0
	if m.filesDir == "" {
		// Start at the home directory, like a file dialog would; fall
		// back to the working directory when there is no home.
		dir, err := os.UserHomeDir()
		if err != nil || dir == "" {
			dir = "."
		}
		m.filesDir = dir
	}
	m.reloadFiles()
	m.view = viewFiles
}

// reloadFiles re-reads the listing of the current directory.
func (m *Model) reloadFiles() {
	m.filesList = listDir(m.filesDir)
	m.applyFilesFilter()
}

// applyFilesFilter recomputes the visible rows from the current query.
func (m *Model) applyFilesFilter() {
	m.filesVis = fuzzyFilter(m.filesList, m.filesQuery)
	if m.filesCur >= len(m.filesVis) {
		m.filesCur = len(m.filesVis) - 1
	}
	if m.filesCur < 0 {
		m.filesCur = 0
	}
}

// listDir returns the display rows for dir: parent link first, then
// subdirectories, then files, dot-entries excluded unless unhidden.
func listDir(dir string) []string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var dirs, files []string
	for _, e := range ents {
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		if e.IsDir() {
			dirs = append(dirs, name+"/")
		} else {
			files = append(files, name)
		}
	}
	sort.Strings(dirs)
	sort.Strings(files)
	out := make([]string, 0, len(dirs)+len(files)+1)
	if parent := filepath.Dir(dir); parent != dir {
		out = append(out, "../")
	}
	out = append(out, dirs...)
	out = append(out, files...)
	return out
}

// handleFiles dispatches keys for the file picker. The vim-style letter
// keys (j/k/h/l) only navigate while the filter is empty: once the user is
// typing a query, every printable rune belongs to the query — the arrow
// keys and enter keep working for navigation either way.
func (m Model) handleFiles(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.filesQuery == "" {
		return m.handleFilesNav(msg)
	}
	return m.handleFilesQuery(msg)
}

// handleFilesNav handles keys while no filter is active.
func (m Model) handleFilesNav(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit

	case m.km.Back:
		// The picker remembers nothing that needs undoing; leaving is
		// cancellation.
		m.view = m.binFrom
		return m, nil

	case "up", "k":
		if m.filesCur > 0 {
			m.filesCur--
		}
	case "down", "j":
		if m.filesCur < len(m.filesVis)-1 {
			m.filesCur++
		}

	case "left", "h":
		if parent := filepath.Dir(m.filesDir); parent != m.filesDir {
			m.filesDir = parent
			m.reloadFiles()
		}

	case "S": // choose the current directory (extract destination)
		if m.pickDir {
			cmd := m.extractCmd(m.binName, m.filesDir)
			m.view = m.binFrom
			return m, cmd
		}

	case m.km.Enter, "l", "right":
		return m.filesOpen()

	case "backspace", "ctrl+h", "ctrl+u":
		// Nothing to edit yet; ignore.

	default:
		runes := []rune(msg.String())
		if len(runes) == 1 && isPrintable(runes[0]) {
			m.filesQuery += string(runes[0])
			m.applyFilesFilter()
		}
	}
	return m, nil
}

// handleFilesQuery handles keys while a filter is being typed.
func (m Model) handleFilesQuery(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit

	case m.km.Back:
		m.view = m.binFrom
		return m, nil

	case "up":
		if m.filesCur > 0 {
			m.filesCur--
		}
	case "down":
		if m.filesCur < len(m.filesVis)-1 {
			m.filesCur++
		}

	case "S":
		if m.pickDir {
			cmd := m.extractCmd(m.binName, m.filesDir)
			m.view = m.binFrom
			return m, cmd
		}

	case m.km.Enter, "right":
		return m.filesOpen()

	case "backspace", "ctrl+h":
		r := []rune(m.filesQuery)
		if len(r) > 0 {
			m.filesQuery = string(r[:len(r)-1])
			m.applyFilesFilter()
		}
	case "ctrl+u":
		m.filesQuery = ""
		m.applyFilesFilter()

	default:
		runes := []rune(msg.String())
		if len(runes) == 1 && isPrintable(runes[0]) {
			m.filesQuery += string(runes[0])
			m.applyFilesFilter()
		}
	}
	return m, nil
}

// filesOpen acts on the selected row: parent, directory or file.
func (m Model) filesOpen() (tea.Model, tea.Cmd) {
	if len(m.filesVis) == 0 {
		return m, nil
	}
	name := m.filesVis[m.filesCur]
	switch {
	case name == "../":
		if parent := filepath.Dir(m.filesDir); parent != m.filesDir {
			m.filesDir = parent
			m.reloadFiles()
		}
	case strings.HasSuffix(name, "/"):
		m.filesDir = filepath.Join(m.filesDir, strings.TrimSuffix(name, "/"))
		m.filesQuery = ""
		m.reloadFiles()
	default:
		if m.pickDir {
			m.status = "S: extract into the current directory"
			return m, nil
		}
		m.binFile = filepath.Join(m.filesDir, name)
		m.binName = defaultBinName(m.binFile, m.binContext)
		m.view = viewBinName
	}
	return m, nil
}

// viewFiles renders the file picker.
func (m Model) viewFiles() string {
	var b strings.Builder
	title := "attach file"
	if m.pickDir {
		title = "extract to"
	}
	fmt.Fprintf(&b, "  %s %s\n", m.st.header.Render(title+":"), m.st.bold.Render(m.filesDir))
	if m.filesQuery != "" {
		fmt.Fprintf(&b, "  %s %s\n", m.st.dimmed.Render("filter:"), m.filesQuery)
	}
	fmt.Fprintln(&b)

	if len(m.filesVis) == 0 {
		fmt.Fprintln(&b, m.st.dimmed.Render("  (empty)"))
	} else {
		avail := m.height - 6
		if avail < 1 {
			avail = 1
		}
		start, end := scrollWindow(m.filesCur, len(m.filesVis), avail)
		for i := start; i < end; i++ {
			name := m.filesVis[i]
			line := truncate("  "+name, m.width)
			if i == m.filesCur {
				fmt.Fprintf(&b, "%s\n", m.st.selected.Render(line))
			} else if strings.HasSuffix(name, "/") {
				fmt.Fprintf(&b, "%s\n", m.st.branch.Render(line))
			} else {
				fmt.Fprintf(&b, "%s\n", line)
			}
		}
	}

	hints := "enter:open  type:filter  esc:cancel"
	if m.pickDir {
		hints = "enter:open dir  S:choose this dir  type:filter  esc:cancel"
	}
	bar := m.statusBar(hints)
	return b.String() + bar
}

// --- view: attachment name ---

// defaultBinName proposes the entry name for an attached file: the file's
// base name with the .b64 suffix the binary convention requires. When the
// picker was opened from an entry, that entry's name wins — attaching to
// "bank/card" naturally produces "bank/card.b64".
func defaultBinName(file, fromEntry string) string {
	if fromEntry != "" && !binary.IsBinary(fromEntry) {
		return fromEntry + ".b64"
	}
	base := filepath.Base(file)
	if !binary.IsBinary(base) {
		base += ".b64"
	}
	return base
}

// handleBinName dispatches keys for the attachment-name input.
func (m Model) handleBinName(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		if m.binName == "" {
			m.status = "binary: name cannot be empty"
			return m, nil
		}
		if !binary.IsBinary(m.binName) {
			m.binName += ".b64"
		}
		if m.store.Exists(m.binName) {
			m.confirmAction = "bin-overwrite"
			m.confirmTarget = m.binName
			m.confirmFocus = 1 // default to "no" — overwriting is destructive.
			m.view = viewConfirm
			return m, nil
		}
		cmd := m.attachCmd(m.binFile, m.binName)
		m.view = m.binFrom
		return m, cmd

	case m.km.Back:
		// Back to the picker, e.g. to pick a different file.
		m.view = viewFiles
		return m, nil

	default:
		applyInputKey(&m.binName, msg)
	}
	return m, nil
}

// viewBinName renders the attachment-name input.
func (m Model) viewBinName() string {
	var b strings.Builder
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "  %s %s\n", m.st.header.Render("attach:"), m.st.bold.Render(m.binFile))
	fmt.Fprintf(&b, "  %s %s\n", m.st.dimmed.Render("as:"), m.st.visible.Render(m.binName)+"▏")
	fmt.Fprintf(&b, "\n  %s\n", m.st.dimmed.Render("enter:encrypt into store  esc:re-pick file"))
	return b.String()
}

// attachCmd returns a command that encrypts the picked file into the store
// through the same pkg/binary path the CLI `binary` command uses.
func (m Model) attachCmd(path, name string) tea.Cmd {
	s := m.store
	return func() tea.Msg {
		f, err := os.Open(path) //nolint:gosec // user-picked path is intentional.
		if err != nil {
			return binResult{err: err}
		}
		defer func() { _ = f.Close() }()
		sum, err := binary.StoreAndHash(s, name, f)
		if err != nil {
			return binResult{err: err}
		}
		return binResult{desc: fmt.Sprintf("stored %s (sha256 %s…)", name, sum[:12])}
	}
}

// extractCmd returns a command that decodes a .b64 entry into dir. It never
// overwrites: an existing file at the destination aborts the extraction
// rather than clobbering data the user can not see from the TUI.
func (m Model) extractCmd(entry, dir string) tea.Cmd {
	s := m.store
	return func() tea.Msg {
		target := filepath.Join(dir, strings.TrimSuffix(filepath.Base(entry), ".b64"))
		// The path is built from a user-chosen directory and the
		// sanitized entry name, and O_EXCL below refuses to clobber.
		f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // user-chosen destination.
		if err != nil {
			return binResult{err: err}
		}
		if err := binary.Cat(s, entry, f); err != nil {
			_ = f.Close()
			_ = os.Remove(target) // no half-written files left behind.
			return binResult{err: err}
		}
		if err := f.Close(); err != nil {
			return binResult{err: err}
		}
		return binResult{desc: "extracted " + entry + " to " + target}
	}
}

// --- binary entries in the detail view ---

// binStats computes the decoded size and SHA-256 of a decrypted binary
// entry, streaming: the base64 text is already in memory, but the decoded
// bytes are not materialised.
func binStats(sec *secret.Secret) (size int64, sum string) {
	dec := base64.NewDecoder(base64.StdEncoding, strings.NewReader(sec.String()))
	h := sha256.New()
	n, err := io.Copy(h, dec)
	if err != nil {
		return n, ""
	}
	return n, fmt.Sprintf("%x", h.Sum(nil))
}

// humanSize renders a byte count the way a file dialog would.
func humanSize(n int64) string {
	switch {
	case n >= 1024*1024:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1024*1024))
	case n >= 1024:
		return fmt.Sprintf("%.1f KiB", float64(n)/1024)
	default:
		return fmt.Sprintf("%d B", n)
	}
}
