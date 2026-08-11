package tui

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/71g3pf4c3/binpass/internal/config"
	"github.com/71g3pf4c3/binpass/pkg/clip"
	"github.com/71g3pf4c3/binpass/pkg/otp"
	"github.com/71g3pf4c3/binpass/pkg/pwgen"
	"github.com/71g3pf4c3/binpass/pkg/secret"
	"github.com/71g3pf4c3/binpass/pkg/vcs"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Store is the subset of the store.Store surface that the TUI needs.
// Defining it here decouples the TUI from the concrete store type, which
// makes the model testable without a real filesystem.
type Store interface {
	List(sub string) ([]string, error)
	Get(name string) (*secret.Secret, error)
	Set(name string, sec *secret.Secret) error
	Remove(name string) error
	Move(from, to string) error
	Exists(name string) bool
	Dir() string
}

// View identifies which screen is active. The model is a state machine that
// transitions between views in response to key events.
type View int

const (
	viewTree     View = iota // top-level tree browser
	viewSearch               // fuzzy search input
	viewDetail               // decrypted entry view
	viewConfirm              // destructive action confirmation
	viewRename               // rename input
	viewGenerate             // generate new password
	viewInsert               // insert new entry
	viewHistory              // git history for an entry
	viewLocked               // autolock screen
)

// tickMsg is sent every second to drive the OTP countdown timer and the
// autolock idle check.
type tickMsg time.Time

// unlockResult carries the outcome of an attempted decryption when the user
// opens an entry. This is delivered asynchronously so that a hardware token
// touch does not freeze the TUI.
type unlockResult struct {
	sec *secret.Secret
	err error
}

// statusMsg carries an informational message to display in the status bar.
type statusMsg string

// generateResult carries the outcome of a password generation attempt.
type generateResult struct {
	password string
	err      error
}

// historyResult carries the outcome of an async git log query.
type historyResult struct {
	commits []vcs.Commit
	err     error
}

// Model is the bubbletea Model for the binpass TUI.
type Model struct {
	store Store
	cfg   config.Config
	km    keymap
	st    styles

	// State machine.
	view View

	// Tree view.
	tree   *treeNode
	flat   []flatItem
	cursor int

	// Cached entry list (avoids store.List on every keystroke in search).
	allEntries []string

	// Search view.
	query    string
	filtered []string
	srchCur  int

	// Detail view.
	current   string         // entry path being viewed
	sec       *secret.Secret // decrypted content (nil until unlocked)
	unlockErr error          // non-nil when decryption failed
	showPass  bool           // toggle password visibility
	otpCfg    *otp.Config    // parsed OTP config, nil if entry has none
	otpCode   string         // current OTP code
	otpRemain int            // seconds until next TOTP code

	// Confirm view.
	confirmAction string // "delete"
	confirmTarget string
	confirmFocus  int // 0 = yes, 1 = no

	// Rename view.
	renameFrom string
	renameTo   string

	// Generate view.
	genTarget  string
	genLength  int
	genPreview string

	// Insert view.
	insertName     string // new entry name (user types it)
	insertPassword string // generated password (filled async)
	insertStep     int    // 0 = name input, 1 = password preview, 2 = done

	// History view.
	histTarget string       // entry name
	histList   []vcs.Commit // commit history
	histCur    int          // selected commit index
	histErr    error

	// VCS backend (nil when the store is not a git repo).
	vcs vcs.Backend

	// Autolock.
	lastActivity time.Time
	locked       bool

	// Clipboard.
	clipBackend clip.Backend

	// Terminal dimensions.
	width  int
	height int

	// Status message (shown in status bar, cleared on next action).
	status string
}

// Options carries the dependencies needed to build the TUI model.
type Options struct {
	Store Store
	Cfg   config.Config
}

// NewModel returns a Model ready to run. The store is read lazily (tree is
// built from List, entries are decrypted on demand).
func NewModel(opts Options) (Model, error) {
	entries, err := opts.Store.List("")
	if err != nil {
		return Model{}, fmt.Errorf("tui: listing store: %w", err)
	}

	tree := buildTree(entries)
	// Expand the root's children so that the initial view is not empty,
	// but do not expand deeper — the user opens directories themselves.
	for _, child := range tree.children {
		if !child.entry {
			child.expanded = true
		}
	}
	flat := flatten(tree)

	noColor := opts.Cfg.NoColor
	km := defaultKeymap()
	st := newStyles(noColor)

	cb, _ := clip.Detect(opts.Cfg.XSelection)
	// Clip backend may be nil (e.g. headless CI). Operations that need it
	// will report the error at the point of use.

	return Model{
		store:        opts.Store,
		cfg:          opts.Cfg,
		km:           km,
		st:           st,
		view:         viewTree,
		tree:         tree,
		flat:         flat,
		cursor:       0,
		allEntries:   entries,
		lastActivity: time.Now(),
		clipBackend:  cb,
		vcs:          vcs.DetectBackend(opts.Store.Dir()),
	}, nil
}

// Run starts the TUI event loop. It returns the process exit code.
func Run(opts Options) int {
	if os.Getenv("TERM") == "dumb" {
		fmt.Fprintln(opts.Cfg.ErrWriter, "tui: requires a real terminal (TERM=dumb)")
		return 1
	}
	m, err := NewModel(opts)
	if err != nil {
		fmt.Fprintf(opts.Cfg.ErrWriter, "tui: %s\n", err)
		return 1
	}
	p := tea.NewProgram(m,
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(), // optional mouse for scrolling
	)
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(opts.Cfg.ErrWriter, "tui: %s\n", err)
		return 1
	}
	return 0
}

// Init implements bubbletea.Model.
func (m Model) Init() tea.Cmd {
	return tickCmd()
}

// Update implements bubbletea.Model.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tickMsg:
		// OTP countdown and autolock check.
		if m.locked {
			return m, tickCmd()
		}
		// Autolock: 5 minutes of inactivity.
		if !m.lastActivity.IsZero() && time.Since(m.lastActivity) > 5*time.Minute {
			m.lock()
			return m, tickCmd()
		}
		// OTP timer.
		m.updateOTP()
		return m, tickCmd()

	case statusMsg:
		m.status = string(msg)
		return m, nil

	case unlockResult:
		if msg.err != nil {
			m.unlockErr = msg.err
			m.sec = nil
		} else {
			m.sec = msg.sec
			m.unlockErr = nil
			m.initOTP()
		}
		return m, nil

	case generateResult:
		if msg.err != nil {
			m.status = "generate: " + msg.err.Error()
			return m, nil
		}
		if m.view == viewInsert {
			m.insertPassword = msg.password
		} else {
			m.genPreview = msg.password
		}
		return m, nil

	case historyResult:
		if msg.err != nil {
			m.histErr = msg.err
			return m, nil
		}
		m.histList = msg.commits
		m.histCur = 0
		return m, nil

	case tea.KeyMsg:
		if m.locked {
			return m.handleLocked(msg)
		}
		m.lastActivity = time.Now()
		m.status = ""

		switch m.view {
		case viewTree:
			return m.handleTree(msg)
		case viewSearch:
			return m.handleSearch(msg)
		case viewDetail:
			return m.handleDetail(msg)
		case viewConfirm:
			return m.handleConfirm(msg)
		case viewRename:
			return m.handleRename(msg)
		case viewGenerate:
			return m.handleGenerate(msg)
		case viewInsert:
			return m.handleInsert(msg)
		case viewHistory:
			return m.handleHistory(msg)
		}

	case tea.MouseMsg:
		if m.locked {
			return m, nil
		}
		return m.handleMouse(msg)
	}

	return m, nil
}

// View implements bubbletea.Model.
func (m Model) View() string {
	if m.locked {
		return m.viewLocked()
	}
	switch m.view {
	case viewTree:
		return m.viewTree()
	case viewSearch:
		return m.viewSearch()
	case viewDetail:
		return m.viewDetail()
	case viewConfirm:
		return m.viewConfirm()
	case viewRename:
		return m.viewRename()
	case viewGenerate:
		return m.viewGenerate()
	case viewInsert:
		return m.viewInsert()
	case viewHistory:
		return m.viewHistory()
	}
	return ""
}

// --- view: tree ---

func (m Model) handleTree(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case m.km.Quit, "ctrl+c":
		return m, tea.Quit

	case m.km.Up, "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case m.km.Down, "j":
		if m.cursor < len(m.flat)-1 {
			m.cursor++
		}

	case "pgdown", "ctrl+d":
		ps := m.pageSize()
		m.cursor += ps
		if m.cursor >= len(m.flat) {
			m.cursor = len(m.flat) - 1
		}
	case "pgup", "ctrl+u":
		ps := m.pageSize()
		m.cursor -= ps
		if m.cursor < 0 {
			m.cursor = 0
		}

	case "G": // shift+g = jump to bottom
		m.cursor = len(m.flat) - 1
	case "g": // gg = jump to top (if pressed twice; first g is a no-op from tree)
		m.cursor = 0

	case m.km.Enter, "l":
		if len(m.flat) == 0 {
			return m, nil
		}
		item := m.flat[m.cursor]
		if item.node.entry {
			m.openEntry(item.node.path)
			return m, m.unlockCmd(item.node.path)
		}
		// Directory: toggle expand.
		item.node.expanded = !item.node.expanded
		m.flat = flatten(m.tree)

	case m.km.Collapse:
		if len(m.flat) > 0 {
			item := m.flat[m.cursor]
			if !item.node.entry {
				item.node.expanded = false
				m.flat = flatten(m.tree)
			}
		}

	case m.km.Search:
		m.view = viewSearch
		m.query = ""
		m.filtered = nil
		m.srchCur = 0

	case m.km.NewEntry:
		m.insertName = ""
		m.insertPassword = ""
		m.insertStep = 0
		m.view = viewInsert

	case "E": // shift+e = expand all
		expandAll(m.tree)
		m.flat = flatten(m.tree)

	case "C": // shift+c = collapse all
		collapseAll(m.tree)
		m.flat = flatten(m.tree)
		m.cursor = 0
	}

	return m, nil
}

func (m Model) viewTree() string {
	if m.width == 0 {
		return "loading..."
	}

	var b strings.Builder
	avail := m.height - 2 // reserve status bar + header
	if avail < 1 {
		avail = 1
	}

	// Scroll window: keep cursor visible.
	start, end := scrollWindow(m.cursor, len(m.flat), avail)

	for i := start; i < end && i < len(m.flat); i++ {
		item := m.flat[i]
		prefix := indent(item.depth)
		var label string
		if item.node.entry {
			label = item.node.name
		} else {
			expand := "▸ "
			if item.node.expanded {
				expand = "▾ "
			}
			label = expand + item.node.name + "/"
		}

		line := prefix + label
		// Truncate to width using display-cell measurement.
		line = truncate(line, m.width)

		if i == m.cursor {
			fmt.Fprintf(&b, "%s\n", m.st.selected.Render(line))
		} else if item.node.entry {
			fmt.Fprintf(&b, "%s\n", m.st.leaf.Render(line))
		} else {
			fmt.Fprintf(&b, "%s\n", m.st.branch.Render(line))
		}
	}

	// Status bar.
	bar := m.statusBar("q:quit  /:search  n:new  enter:open  h:collapse  E:expand-all  C:collapse-all  j/k:nav")
	return b.String() + bar
}

// --- view: search ---

func (m Model) handleSearch(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case m.km.ClearSearch:
		m.view = viewTree
		m.query = ""
		m.filtered = nil
		return m, nil

	case "enter":
		if len(m.filtered) > 0 && m.srchCur < len(m.filtered) {
			name := m.filtered[m.srchCur]
			m.openEntry(name)
			return m, m.unlockCmd(name)
		}
		return m, nil

	case "up", "k":
		if m.srchCur > 0 {
			m.srchCur--
		}
	case "down", "j":
		if m.srchCur < len(m.filtered)-1 {
			m.srchCur++
		}

	default:
		// Typing: append printable chars, backspace removes last char.
		runes := []rune(msg.String())
		if len(runes) == 1 {
			ch := runes[0]
			switch {
			case ch == 127 || ch == 8: // backspace / ctrl+h
				if len(m.query) > 0 {
					m.query = m.query[:len(m.query)-1]
				}
			case isPrintable(ch):
				m.query += string(ch)
			}
		}
		// Re-filter from cached list.
		m.filtered = fuzzyFilter(m.allEntries, m.query)
		if m.srchCur >= len(m.filtered) {
			m.srchCur = 0
		}
	}
	return m, nil
}

func (m Model) viewSearch() string {
	var b strings.Builder
	fmt.Fprintf(&b, "  %s/%s\n\n", m.st.search.Render("search"), m.st.bold.Render(m.query))

	if len(m.filtered) == 0 && m.query != "" {
		fmt.Fprintln(&b, m.st.dimmed.Render("  no matches"))
	} else {
		maxShow := m.height - 5
		if maxShow < 1 {
			maxShow = 1
		}
		start, end := scrollWindow(m.srchCur, len(m.filtered), maxShow)
		for i := start; i < end; i++ {
			name := m.filtered[i]
			if i == m.srchCur {
				fmt.Fprintf(&b, "  %s\n", m.st.selected.Render(name))
			} else {
				fmt.Fprintf(&b, "  %s\n", name)
			}
		}
	}

	bar := m.statusBar("esc:back  enter:open  type to filter")
	return b.String() + bar
}

// --- view: detail ---

func (m Model) handleDetail(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case m.km.Back:
		m.closeEntry()
		return m, nil

	case m.km.TogglePassword:
		m.showPass = !m.showPass

	case m.km.CopyPassword:
		if m.sec != nil {
			return m, m.copyPasswordCmd()
		}

	case m.km.CopyOTP:
		if m.otpCode != "" {
			return m, m.copyOTPCodeCmd()
		}

	case m.km.Delete:
		m.confirmAction = "delete"
		m.confirmTarget = m.current
		m.confirmFocus = 1 // default to "no"
		m.view = viewConfirm

	case m.km.Rename:
		m.renameFrom = m.current
		m.renameTo = m.current
		m.view = viewRename

	case m.km.Generate:
		m.genTarget = m.current
		m.genLength = m.cfg.GeneratedLength
		m.genPreview = ""
		m.view = viewGenerate
		return m, m.generateCmd(m.genLength)

	case m.km.History:
		m.histTarget = m.current
		m.histList = nil
		m.histErr = nil
		m.histCur = 0
		m.view = viewHistory
		return m, m.historyCmd(m.current)

	case m.km.Quit, "ctrl+c":
		return m, tea.Quit
	}
	return m, nil
}

func (m Model) viewDetail() string {
	var b strings.Builder
	fmt.Fprintf(&b, "  %s %s\n\n", m.st.header.Render("▸"), m.st.bold.Render(m.current))

	if m.unlockErr != nil {
		fmt.Fprintf(&b, "  %s %s\n", m.st.errorMsg.Render("error:"), m.unlockErr)
		bar := m.statusBar("esc:back")
		return b.String() + bar
	}

	if m.sec == nil {
		fmt.Fprintln(&b, m.st.dimmed.Render("  decrypting..."))
		bar := m.statusBar("esc:back")
		return b.String() + bar
	}

	// Password line — masked by default.
	pw := m.sec.Password()
	if m.showPass {
		fmt.Fprintf(&b, "  %s %s\n", m.st.dimmed.Render("pass:"), m.st.visible.Render(pw))
	} else {
		fmt.Fprintf(&b, "  %s %s\n", m.st.dimmed.Render("pass:"), m.st.masked.Render(maskPassword(pw)))
	}

	// Fields.
	for _, f := range m.sec.Fields() {
		fmt.Fprintf(&b, "  %s %s\n", m.st.dimmed.Render(f.Key+":"), f.Value)
	}

	// OTP.
	if m.otpCfg != nil {
		fmt.Fprintf(&b, "\n  %s %s%ds\n",
			m.st.otpCode.Render("OTP: "+m.otpCode),
			m.st.dimmed.Render("expires in "),
			m.otpRemain,
		)
	}

	// Remaining body lines (free text after fields).
	lines := m.sec.Lines()
	if len(lines) > 1 {
		fmt.Fprintln(&b)
		for _, line := range lines[1:] {
			// Skip otpauth:// lines (already rendered above) and key: value
			// lines (already rendered as fields).
			if strings.HasPrefix(line, "otpauth://") {
				continue
			}
			if _, _, ok := splitField(line); ok {
				continue
			}
			fmt.Fprintf(&b, "  %s\n", line)
		}
	}

	bar := m.statusBar("p:toggle  c:copy  o:otp  d:delete  r:rename  g:generate  y:history  esc:back")
	return b.String() + bar
}

// --- view: confirm ---

func (m Model) handleConfirm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "left", "h":
		if m.confirmFocus > 0 {
			m.confirmFocus--
		}
	case "right", "l":
		if m.confirmFocus < 1 {
			m.confirmFocus++
		}
	case "enter":
		if m.confirmFocus == 0 {
			// Confirmed.
			switch m.confirmAction {
			case "delete":
				if err := m.store.Remove(m.confirmTarget); err != nil {
					m.status = fmt.Sprintf("delete failed: %s", err)
				} else {
					m.status = "deleted " + m.confirmTarget
				}
			}
			m.closeEntry()
			m.rebuildTree()
		}
		// Cancelled or done.
		m.view = viewTree
		return m, nil

	case m.km.Back:
		m.view = viewDetail
		return m, nil
	}
	return m, nil
}

func (m Model) viewConfirm() string {
	var b strings.Builder
	fmt.Fprintln(&b)
	action := m.confirmAction
	fmt.Fprintf(&b, "  %s %s?\n\n", m.st.confirm.Render(action+":"), m.st.bold.Render(m.confirmTarget))

	yes := " [Yes] "
	no := "  No  "
	if m.confirmFocus == 0 {
		yes = m.st.selected.Render(yes)
	} else {
		no = m.st.selected.Render(no)
	}
	fmt.Fprintf(&b, "  %s%s\n", yes, no)
	bar := m.statusBar("enter:confirm  esc:cancel")
	return b.String() + bar
}

// --- view: rename ---

func (m Model) handleRename(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		if m.renameTo == "" {
			m.status = "rename: name cannot be empty"
			return m, nil
		}
		if m.renameTo == m.renameFrom {
			m.view = viewDetail
			return m, nil
		}
		if err := m.store.Move(m.renameFrom, m.renameTo); err != nil {
			m.status = "rename: " + err.Error()
			m.view = viewDetail
			return m, nil
		}
		m.status = "renamed to " + m.renameTo
		m.closeEntry()
		m.rebuildTree()
		return m, nil

	case m.km.Back:
		m.view = viewDetail
		return m, nil

	case "ctrl+u": // clear input
		m.renameTo = ""

	case "backspace":
		if len(m.renameTo) > 0 {
			m.renameTo = m.renameTo[:len(m.renameTo)-1]
		}

	default:
		runes := []rune(msg.String())
		if len(runes) == 1 && isPrintable(runes[0]) {
			m.renameTo += string(runes[0])
		}
	}
	return m, nil
}

func (m Model) viewRename() string {
	var b strings.Builder
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "  %s %s\n", m.st.header.Render("rename:"), m.st.bold.Render(m.renameFrom))
	fmt.Fprintf(&b, "  %s %s\n", m.st.dimmed.Render("to:"), m.renameTo)
	fmt.Fprintf(&b, "\n  %s\n", m.st.dimmed.Render("enter:confirm  esc:cancel  ctrl+u:clear"))
	return b.String()
}

// --- view: generate ---

func (m Model) handleGenerate(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		if m.genPreview == "" {
			return m, nil
		}
		// Apply: set the new password on the entry.
		sec := m.sec
		if sec == nil {
			// Entry was not decrypted (should not happen from detail view).
			m.status = "generate: entry not decrypted"
			m.view = viewDetail
			return m, nil
		}
		sec.SetPassword(m.genPreview)
		if err := m.store.Set(m.genTarget, sec); err != nil {
			m.status = "generate: " + err.Error()
		} else {
			m.status = "generated new password for " + m.genTarget
			// Re-decrypt to reflect the updated entry.
			m.sec = sec
		}
		m.view = viewDetail
		return m, nil

	case "r": // regenerate
		return m, m.generateCmd(m.genLength)

	case m.km.Back:
		m.view = viewDetail
		return m, nil
	}
	return m, nil
}

func (m Model) viewGenerate() string {
	var b strings.Builder
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "  %s %s\n", m.st.header.Render("generate:"), m.st.bold.Render(m.genTarget))
	if m.genPreview != "" {
		fmt.Fprintf(&b, "  %s %s\n", m.st.dimmed.Render("new:"), m.st.visible.Render(m.genPreview))
	} else {
		fmt.Fprintln(&b, m.st.dimmed.Render("  generating..."))
	}
	fmt.Fprintf(&b, "\n  %s\n", m.st.dimmed.Render("enter:apply  r:regenerate  esc:cancel"))
	return b.String()
}

// --- view: history ---

func (m Model) handleHistory(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case m.km.Back, "q":
		m.view = viewDetail
		return m, nil

	case "up", "k":
		if m.histCur > 0 {
			m.histCur--
		}
	case "down", "j":
		if m.histCur < len(m.histList)-1 {
			m.histCur++
		}
	}
	return m, nil
}

func (m Model) viewHistory() string {
	var b strings.Builder
	fmt.Fprintf(&b, "  %s %s\n\n", m.st.header.Render("history:"), m.st.bold.Render(m.histTarget))

	if m.histErr != nil {
		fmt.Fprintf(&b, "  %s %s\n", m.st.errorMsg.Render("error:"), m.histErr)
		bar := m.statusBar("esc:back")
		return b.String() + bar
	}

	if len(m.histList) == 0 {
		fmt.Fprintln(&b, m.st.dimmed.Render("  no git history (not a git repository or entry not tracked)"))
		bar := m.statusBar("esc:back")
		return b.String() + bar
	}

	avail := m.height - 4
	if avail < 1 {
		avail = 1
	}
	start, end := scrollWindow(m.histCur, len(m.histList), avail)
	for i := start; i < end; i++ {
		c := m.histList[i]
		ts := c.Date.Format("2006-01-02 15:04")
		line := fmt.Sprintf("  %s  %s  %s", c.Hash, ts, c.Subject)
		// Truncate to width.
		line = truncate(line, m.width)
		if i == m.histCur {
			fmt.Fprintf(&b, "%s\n", m.st.selected.Render(line))
		} else {
			fmt.Fprintf(&b, "%s\n", m.st.dimmed.Render(line))
		}
	}

	bar := m.statusBar("j/k:nav  esc:back")
	return b.String() + bar
}

// --- view: insert ---

func (m Model) handleInsert(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch m.insertStep {
	case 0: // name input
		switch msg.String() {
		case "enter":
			if m.insertName == "" {
				m.status = "insert: name cannot be empty"
				return m, nil
			}
			if m.store.Exists(m.insertName) {
				m.status = "insert: entry already exists"
				return m, nil
			}
			// Generate password and move to preview.
			m.insertStep = 1
			return m, m.insertGenerateCmd(m.cfg.GeneratedLength)

		case m.km.Back:
			m.view = viewTree
			return m, nil

		case "ctrl+u":
			m.insertName = ""

		case "backspace":
			if len(m.insertName) > 0 {
				m.insertName = m.insertName[:len(m.insertName)-1]
			}

		default:
			runes := []rune(msg.String())
			if len(runes) == 1 && isPrintable(runes[0]) {
				m.insertName += string(runes[0])
			}
		}

	case 1: // password preview
		switch msg.String() {
		case "enter":
			// Apply: write to store.
			sec := secret.New(m.insertPassword, "")
			if err := m.store.Set(m.insertName, sec); err != nil {
				m.status = "insert: " + err.Error()
				m.view = viewTree
				return m, nil
			}
			m.status = "created " + m.insertName
			m.rebuildTree()
			m.view = viewTree
			return m, nil

		case "r": // regenerate
			return m, m.insertGenerateCmd(m.cfg.GeneratedLength)

		case m.km.Back:
			m.insertStep = 0 // back to name input
		}

	case 2: // done — should not be reachable, return to tree.
		m.view = viewTree
	}
	return m, nil
}

func (m Model) viewInsert() string {
	var b strings.Builder
	fmt.Fprintln(&b)

	switch m.insertStep {
	case 0:
		fmt.Fprintf(&b, "  %s\n", m.st.header.Render("new entry"))
		fmt.Fprintf(&b, "  %s %s\n", m.st.dimmed.Render("name:"), m.insertName)
		fmt.Fprintf(&b, "  %s\n", m.st.dimmed.Render("_"))
		fmt.Fprintf(&b, "\n  %s\n", m.st.dimmed.Render("enter:next  esc:cancel  ctrl+u:clear"))

	case 1:
		fmt.Fprintf(&b, "  %s %s\n", m.st.header.Render("new entry:"), m.st.bold.Render(m.insertName))
		if m.insertPassword != "" {
			fmt.Fprintf(&b, "  %s %s\n", m.st.dimmed.Render("pass:"), m.st.visible.Render(m.insertPassword))
		} else {
			fmt.Fprintln(&b, m.st.dimmed.Render("  generating..."))
		}
		fmt.Fprintf(&b, "\n  %s\n", m.st.dimmed.Render("enter:save  r:regenerate  esc:back"))
	}

	return b.String()
}

// insertGenerateCmd returns a tea.Cmd that generates a password for the new entry.
func (m Model) insertGenerateCmd(length int) tea.Cmd {
	charset := m.cfg.CharacterSet
	return func() tea.Msg {
		pw, err := pwgen.Generate(length, charset)
		if err != nil {
			return generateResult{err: err}
		}
		return generateResult{password: pw}
	}
}

// --- view: locked ---

func (m Model) handleLocked(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Any key unlocks — the user must re-enter the entry to decrypt.
	// This is intentional: we clear the decrypted secret from memory.
	m.locked = false
	m.sec = nil
	m.otpCfg = nil
	m.otpCode = ""
	m.view = viewTree
	return m, nil
}

func (m Model) viewLocked() string {
	var b strings.Builder
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, m.st.confirm.Render("  session locked (5 min idle)"))
	fmt.Fprintln(&b, m.st.dimmed.Render("  press any key to return to tree"))
	return b.String()
}

// --- helpers ---

// pageSize returns the number of visible lines in the current view.
func (m Model) pageSize() int {
	ps := m.height - 2
	if ps < 1 {
		ps = 1
	}
	return ps
}

// handleMouse processes mouse events (scroll wheel).
func (m Model) handleMouse(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
	switch msg.Action {
	case tea.MouseActionPress:
		switch msg.Button {
		case tea.MouseButtonWheelUp:
			switch m.view {
			case viewTree:
				if m.cursor > 2 {
					m.cursor -= 3
				} else {
					m.cursor = 0
				}
			case viewSearch:
				if m.srchCur > 2 {
					m.srchCur -= 3
				} else {
					m.srchCur = 0
				}
			case viewHistory:
				if m.histCur > 2 {
					m.histCur -= 3
				} else {
					m.histCur = 0
				}
			}
		case tea.MouseButtonWheelDown:
			switch m.view {
			case viewTree:
				if m.cursor < len(m.flat)-3 {
					m.cursor += 3
				} else {
					m.cursor = len(m.flat) - 1
				}
			case viewSearch:
				if m.srchCur < len(m.filtered)-3 {
					m.srchCur += 3
				} else {
					m.srchCur = len(m.filtered) - 1
				}
			case viewHistory:
				if m.histCur < len(m.histList)-3 {
					m.histCur += 3
				} else {
					m.histCur = len(m.histList) - 1
				}
			}
		}
	}
	return m, nil
}

// openEntry switches to the detail view for the given entry. The secret is
// not decrypted yet — that happens asynchronously via unlockCmd.
func (m *Model) openEntry(name string) {
	m.view = viewDetail
	m.current = name
	m.sec = nil
	m.unlockErr = nil
	m.showPass = false
	m.otpCfg = nil
	m.otpCode = ""
	m.otpRemain = 0
}

// closeEntry returns to the tree view and clears the decrypted secret from
// memory.
func (m *Model) closeEntry() {
	m.view = viewTree
	m.sec = nil
	m.current = ""
	m.otpCfg = nil
	m.otpCode = ""
	m.unlockErr = nil
	m.showPass = false
}

// unlockCmd returns a tea.Cmd that decrypts the entry in the background.
func (m Model) unlockCmd(name string) tea.Cmd {
	s := m.store
	return func() tea.Msg {
		sec, err := s.Get(name)
		return unlockResult{sec: sec, err: err}
	}
}

// generateCmd returns a tea.Cmd that generates a new password.
func (m Model) generateCmd(length int) tea.Cmd {
	charset := m.cfg.CharacterSet
	return func() tea.Msg {
		pw, err := pwgen.Generate(length, charset)
		return generateResult{password: pw, err: err}
	}
}

// historyCmd returns a tea.Cmd that loads the git history for an entry.
func (m Model) historyCmd(name string) tea.Cmd {
	backend := m.vcs
	return func() tea.Msg {
		if backend == nil {
			return historyResult{err: fmt.Errorf("not a git repository")}
		}
		commits, err := backend.Log(name, vcs.LogOption{})
		return historyResult{commits: commits, err: err}
	}
}

// initOTP sets up the OTP timer for the current entry, if it has an
// otpauth:// URI.
func (m *Model) initOTP() {
	if m.sec == nil {
		return
	}
	uri, ok := m.sec.OTP()
	if !ok {
		m.otpCfg = nil
		return
	}
	cfg, err := otp.Parse(uri)
	if err != nil {
		m.otpCfg = nil
		return
	}
	m.otpCfg = cfg
	m.updateOTP()
}

// updateOTP refreshes the current OTP code and remaining seconds.
func (m *Model) updateOTP() {
	if m.otpCfg == nil || m.otpCfg.Kind != otp.TOTP {
		return
	}
	now := time.Now()
	code, err := m.otpCfg.Code(now)
	if err != nil {
		return
	}
	m.otpCode = code
	expires := m.otpCfg.Expires(now)
	remain := time.Until(expires).Seconds()
	if remain < 0 {
		remain = 0
	}
	m.otpRemain = int(remain)
}

// copyPasswordCmd returns a tea.Cmd that copies the password to the clipboard.
func (m Model) copyPasswordCmd() tea.Cmd {
	pw := m.sec.Password()
	name := m.current
	cb := m.clipBackend
	dur := m.cfg.ClipTime
	return func() tea.Msg {
		if cb == nil {
			return statusMsg("no clipboard backend")
		}
		ctx, cancel := context.WithTimeout(context.Background(), dur+time.Second)
		defer cancel()
		if err := clip.CopyWithTimeout(ctx, cb, pw, dur); err != nil {
			return statusMsg("clipboard: " + err.Error())
		}
		return statusMsg("copied " + name + " to clipboard")
	}
}

// copyOTPCodeCmd returns a tea.Cmd that copies the current OTP code.
func (m Model) copyOTPCodeCmd() tea.Cmd {
	code := m.otpCode
	cb := m.clipBackend
	dur := m.cfg.ClipTime
	return func() tea.Msg {
		if cb == nil {
			return statusMsg("no clipboard backend")
		}
		ctx, cancel := context.WithTimeout(context.Background(), dur+time.Second)
		defer cancel()
		if err := clip.CopyWithTimeout(ctx, cb, code, dur); err != nil {
			return statusMsg("clipboard: " + err.Error())
		}
		return statusMsg("copied OTP code to clipboard")
	}
}

// lock clears all decrypted secrets from memory.
func (m *Model) lock() {
	m.locked = true
	m.sec = nil
	m.otpCfg = nil
	m.otpCode = ""
	m.showPass = false
	m.view = viewLocked
}

// rebuildTree refreshes the tree from the store (e.g. after a delete or rename).
func (m *Model) rebuildTree() {
	entries, err := m.store.List("")
	if err != nil {
		return
	}
	m.allEntries = entries
	m.tree = buildTree(entries)
	for _, child := range m.tree.children {
		if !child.entry {
			child.expanded = true
		}
	}
	m.flat = flatten(m.tree)
	if m.cursor >= len(m.flat) {
		m.cursor = len(m.flat) - 1
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
}

// statusBar renders a footer line with key hints.
func (m Model) statusBar(hints string) string {
	if m.width == 0 {
		return ""
	}
	left := m.status
	if left == "" {
		left = "binpass"
	}
	right := hints
	pad := m.width - len(left) - len(right) - 2
	if pad < 1 {
		pad = 1
	}
	line := left + strings.Repeat(" ", pad) + right
	line = truncate(line, m.width)
	return "\n" + m.st.statusBar.Render(line)
}

// maskPassword returns a fixed-width mask string. The length does not reveal
// the actual password length, which would be an information leak.
func maskPassword(pw string) string {
	return "••••••••"
}

// truncate clips s to at most maxCells display cells, using lipgloss.Width
// for accurate Unicode measurement. This prevents CJK and emoji from
// overflowing the terminal.
func truncate(s string, maxCells int) string {
	if maxCells <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= maxCells {
		return s
	}
	// Binary search for the longest prefix that fits.
	lo, hi := 0, len(s)
	for lo < hi {
		mid := lo + (hi-lo)/2
		if lipgloss.Width(s[:mid]) <= maxCells {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return s[:lo-1]
}

// indent returns the prefix string for the given tree depth.
func indent(depth int) string {
	if depth <= 0 {
		return ""
	}
	return strings.Repeat("  ", depth)
}

// scrollWindow returns the start (inclusive) and end (exclusive) indices for
// a scrollable window of size h centred on cursor.
func scrollWindow(cursor, total, h int) (start, end int) {
	if total <= h {
		return 0, total
	}
	half := h / 2
	start = cursor - half
	if start < 0 {
		start = 0
	}
	end = start + h
	if end > total {
		end = total
		start = end - h
	}
	if start < 0 {
		start = 0
	}
	return start, end
}

// splitField is a local copy of secret.splitField to avoid exporting it.
// It parses a "key: value" line.
func splitField(line string) (key, value string, ok bool) {
	for i, ch := range line {
		if ch == ':' {
			k := strings.TrimSpace(line[:i])
			v := strings.TrimSpace(line[i+1:])
			if k == "" || strings.ContainsAny(k, " \t") {
				return "", "", false
			}
			if strings.HasPrefix(v, "//") {
				return "", "", false
			}
			return k, v, true
		}
	}
	return "", "", false
}

// tickCmd returns a command that sends a tickMsg after one second.
func tickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// SetSize updates the terminal dimensions (used in tests).
func (m *Model) SetSize(w, h int) {
	m.width = w
	m.height = h
}

// ensure Model satisfies tea.Model at compile time.
var _ tea.Model = Model{}
