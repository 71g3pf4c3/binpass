package tui

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/71g3pf4c3/binpass/internal/config"
	"github.com/71g3pf4c3/binpass/internal/theme"
	"github.com/71g3pf4c3/binpass/pkg/audit"
	"github.com/71g3pf4c3/binpass/pkg/binary"
	"github.com/71g3pf4c3/binpass/pkg/clip"
	"github.com/71g3pf4c3/binpass/pkg/otp"
	"github.com/71g3pf4c3/binpass/pkg/pwgen"
	"github.com/71g3pf4c3/binpass/pkg/secret"
	"github.com/71g3pf4c3/binpass/pkg/store"
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
	Copy(from, to string) error
	RemoveDir(name string) error
	IsDir(name string) bool
	Grep(sub string, match func(string) bool) ([]store.Match, error)
	Exists(name string) bool
	Dir() string
}

// View identifies which screen is active. The model is a state machine that
// transitions between views in response to key events.
type View int

const (
	viewTree      View = iota // top-level tree browser
	viewSearch                // fuzzy search input
	viewDetail                // decrypted entry view
	viewConfirm               // destructive action confirmation
	viewRename                // rename input
	viewGenerate              // generate new password
	viewInsert                // insert new entry
	viewHistory               // git history for an entry
	viewLocked                // autolock screen
	viewEdit                  // staged entry editor
	viewFiles                 // local-filesystem picker (attach/extract)
	viewBinName               // attachment entry-name input
	viewFieldPick             // copy-a-field picker
	viewStatus                // read-only store status (git, sync)
	viewDup                   // duplicate-entry name input
	viewGrep                  // search across decrypted contents
	viewAudit                 // read-only store audit report
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
	fieldCur  int            // selected row in the field picker

	// Confirm view.
	confirmAction string // "delete", "delete-dir", "save-edit", …
	confirmTarget string
	confirmFocus  int  // 0 = yes, 1 = no
	confirmFrom   View // view the confirmation was triggered from

	// Rename view.
	renameFrom string
	renameTo   string

	// Generate view.
	genTarget  string
	genLength  int
	genSymbols bool
	genPreview string

	// Insert view.
	insertName     string // new entry name (user types it)
	insertPassword string // generated password (filled async)
	insertManual   bool   // true when the user types the password by hand
	insertLen      int    // generator length for this insert
	insertSymbols  bool   // generator alphabet for this insert
	insertStep     int    // 0 = name input, 1 = password, 2 = done

	// History view.
	histTarget string       // entry name
	histList   []vcs.Commit // commit history
	histCur    int          // selected commit index
	histErr    error

	// Edit view (staged edits to the open or newly created entry).
	editor    *entryEditor // staged plaintext copy; nil outside the editor
	editName  string       // entry the staged edits belong to
	editNew   bool         // true when the editor is creating a new entry
	editCur   int          // selected row: 0 = password, i+1 = rows[i]
	editMode  int          // editBrowse or one of the input modes
	editInput string       // contents of the bottom input line
	editKey   string       // staged key of the field being added

	// File picker and binary attachments.
	filesDir    string   // directory being browsed
	filesList   []string // its full listing (dirs carry a trailing "/")
	filesVis    []string // query-filtered view of filesList
	filesCur    int      // selected picker row
	filesQuery  string   // fuzzy filter for the listing
	pickDir     bool     // true when choosing an extract destination
	binFrom     View     // view to return to after the picker flow
	binFile     string   // source file of an in-flight attach
	binName     string   // entry name of an in-flight attach or extract
	binContext  string   // entry the attach was initiated from (naming hint)
	binSize     int64    // decoded size of the open binary entry
	binSum      string   // SHA-256 of the open binary entry's content
	binBackdrop bool     // true when the open entry is a .b64 attachment

	// Status view.
	statRes *statusResult // collected store status, nil while loading

	// Duplicate view.
	dupFrom string // entry being duplicated
	dupTo   string // proposed copy name

	// Grep view.
	grepQuery   string        // pattern being typed
	grepMatches []store.Match // results of the last run
	grepErr     error
	grepCur     int  // selected result
	grepDone    bool // true once results are displayed

	// Audit view.
	auditRep *audit.Report // collected audit, nil while loading
	auditErr error
	auditCur int

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
	st := newStyles(noColor, theme.Get(opts.Cfg.Theme))

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
			m.initBinary()
		}
		return m, nil

	case binResult:
		if msg.err != nil {
			m.status = "binary: " + msg.err.Error()
		} else {
			m.status = msg.desc
			m.rebuildTree()
		}
		return m, nil

	case statusResult:
		m.statRes = &msg
		return m, nil

	case hotpResult:
		if msg.err != nil {
			m.status = "otp: " + msg.err.Error()
			return m, nil
		}
		// The stored entry now carries the advanced counter; re-arm the
		// OTP state from it so the next reveal starts from the new one.
		m.sec = msg.sec
		m.initOTP()
		m.status = "HOTP code copied, counter advanced"
		return m, nil

	case grepResult:
		m.grepDone = true
		m.grepErr = msg.err
		m.grepMatches = msg.matches
		m.grepCur = 0
		return m, nil

	case auditResult:
		if msg.err != nil {
			m.auditErr = msg.err
		} else {
			m.auditRep = msg.report
			m.auditCur = 0
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
		case viewEdit:
			return m.handleEdit(msg)
		case viewFiles:
			return m.handleFiles(msg)
		case viewBinName:
			return m.handleBinName(msg)
		case viewFieldPick:
			return m.handleFieldPick(msg)
		case viewStatus:
			return m.handleStatus(msg)
		case viewDup:
			return m.handleDup(msg)
		case viewGrep:
			return m.handleGrep(msg)
		case viewAudit:
			return m.handleAudit(msg)
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
	case viewEdit:
		return m.viewEdit()
	case viewFiles:
		return m.viewFiles()
	case viewBinName:
		return m.viewBinName()
	case viewFieldPick:
		return m.viewFieldPick()
	case viewStatus:
		return m.viewStatus()
	case viewDup:
		return m.viewDup()
	case viewGrep:
		return m.viewGrep()
	case viewAudit:
		return m.viewAudit()
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
		m.insertManual = false
		m.insertLen = m.cfg.GeneratedLength
		m.insertSymbols = true
		m.insertStep = 0
		m.view = viewInsert

	case m.km.Attach:
		// Attach a file to the selected entry: the picker proposes
		// "<entry>.b64" as the store name, matching the CLI convention.
		if len(m.flat) > 0 {
			item := m.flat[m.cursor]
			if item.node.entry && !binary.IsBinary(item.node.path) {
				m.binFrom = viewTree
				m.binContext = item.node.path
				m.startFilePicker(false)
			}
		}

	case "E": // shift+e = expand all
		expandAll(m.tree)
		m.flat = flatten(m.tree)

	case "C": // shift+c = collapse all
		collapseAll(m.tree)
		m.flat = flatten(m.tree)
		m.cursor = 0

	case m.km.Status: // shift+s = store status
		m.statRes = nil
		m.view = viewStatus
		return m, m.statusCmd()

	case m.km.Grep: // shift+f = search decrypted contents
		m.grepQuery = ""
		m.grepMatches = nil
		m.grepErr = nil
		m.grepCur = 0
		m.grepDone = false
		m.view = viewGrep

	case m.km.Audit: // shift+a = store audit
		m.auditRep = nil
		m.auditErr = nil
		m.auditCur = 0
		m.view = viewAudit
		return m, m.auditCmd()

	case m.km.Delete: // delete the selected entry or directory
		if len(m.flat) > 0 {
			item := m.flat[m.cursor]
			if item.node.entry {
				m.confirmAction = "delete"
			} else {
				m.confirmAction = "delete-dir"
			}
			m.confirmTarget = item.node.path
			m.confirmFocus = 1 // default to "no"
			m.confirmFrom = viewTree
			m.view = viewConfirm
		}
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
	bar := m.statusBar("q:quit  /:search  n:new  b:attach  d:delete  F:grep  A:audit  S:status  enter:open  h:collapse  E:expand-all  C:collapse-all  j/k:nav")
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
	if m.binBackdrop {
		return m.handleDetailBinary(msg)
	}
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

	case m.km.CopyField:
		if m.sec != nil {
			m.startFieldPick()
		}

	case m.km.Type:
		if m.sec != nil {
			m.status = "typing in a moment — switch to the target window"
			return m, m.typeValueCmd("password", m.sec.Password())
		}

	case m.km.CopyOTP:
		if m.otpCfg != nil && m.otpCfg.Kind == otp.HOTP && m.sec != nil {
			// HOTP codes do not exist until asked for: revealing one
			// advances the counter and persists it, exactly as the
			// otp command does.
			m.status = "computing HOTP code and advancing the counter..."
			return m, m.hotpRevealCmd()
		}
		if m.otpCode != "" {
			return m, m.copyOTPCodeCmd()
		}

	case m.km.Duplicate:
		if m.sec != nil {
			m.startDup()
		}

	case m.km.Edit:
		if m.sec != nil {
			m.startEdit()
		}

	case m.km.Delete:
		m.confirmAction = "delete"
		m.confirmTarget = m.current
		m.confirmFocus = 1 // default to "no"
		m.confirmFrom = viewDetail
		m.view = viewConfirm

	case m.km.Rename:
		m.renameFrom = m.current
		m.renameTo = m.current
		m.view = viewRename

	case m.km.Duplicate:
		if m.sec != nil {
			m.startDup()
		}

	case m.km.Generate:
		m.genTarget = m.current
		m.genLength = m.cfg.GeneratedLength
		m.genSymbols = true
		m.genPreview = ""
		m.view = viewGenerate
		return m, m.generateCmd(m.genLength, m.genSymbols)

	case m.km.History:
		m.histTarget = m.current
		m.histList = nil
		m.histErr = nil
		m.histCur = 0
		m.view = viewHistory
		return m, m.historyCmd(m.current)

	case m.km.Attach:
		m.binFrom = viewDetail
		m.binContext = m.current
		m.startFilePicker(false)

	case m.km.Quit, "ctrl+c":
		return m, tea.Quit
	}
	return m, nil
}

// handleDetailBinary dispatches keys for a decrypted .b64 entry. Most
// text-entry actions are meaningless or harmful on base64 blobs (editing
// them by hand, generating a password over them, copying them to the
// clipboard), so they are refused rather than silently mangled.
func (m Model) handleDetailBinary(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case m.km.Back:
		m.closeEntry()
		return m, nil

	case m.km.Extract:
		m.binFrom = viewDetail
		m.binName = m.current
		m.startFilePicker(true)

	case m.km.Attach:
		m.binFrom = viewDetail
		m.binContext = "" // a .b64 context must not name the new entry.
		m.startFilePicker(false)

	case m.km.Delete:
		m.confirmAction = "delete"
		m.confirmTarget = m.current
		m.confirmFocus = 1 // default to "no"
		m.confirmFrom = viewDetail
		m.view = viewConfirm

	case m.km.Rename:
		m.renameFrom = m.current
		m.renameTo = m.current
		m.view = viewRename

	case m.km.History:
		m.histTarget = m.current
		m.histList = nil
		m.histErr = nil
		m.histCur = 0
		m.view = viewHistory
		return m, m.historyCmd(m.current)

	case m.km.Quit, "ctrl+c":
		return m, tea.Quit

	default:
		m.status = "binary entry: x:extract  b:attach  d:delete  r:rename"
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

	// Binary attachments: never render the base64 body, only metadata.
	if m.binBackdrop {
		fmt.Fprintf(&b, "  %s\n", m.st.header.Render("binary attachment"))
		fmt.Fprintf(&b, "  %s %s\n", m.st.dimmed.Render("size:"), humanSize(m.binSize))
		if m.binSum != "" {
			fmt.Fprintf(&b, "  %s %s\n", m.st.dimmed.Render("sha256:"), m.binSum)
		}
		bar := m.statusBar("x:extract  b:attach  d:delete  r:rename  y:history  esc:back")
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
		if m.otpCfg.Kind == otp.HOTP {
			fmt.Fprintf(&b, "\n  %s\n",
				m.st.otpCode.Render("OTP: HOTP")+m.st.dimmed.Render("  o: reveal code & advance counter"))
		} else {
			fmt.Fprintf(&b, "\n  %s %s%ds\n",
				m.st.otpCode.Render("OTP: "+m.otpCode),
				m.st.dimmed.Render("expires in "),
				m.otpRemain,
			)
		}
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

	bar := m.statusBar("p:toggle  e:edit  c:copy  C:field  t:type  o:otp  Y:duplicate  d:delete  r:rename  g:generate  y:history  esc:back")
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
		if m.confirmFocus != 0 {
			// Declined. The editor keeps its staged copy so the user
			// can reconsider; the delete flow keeps its historical
			// "back to the tree" behaviour.
			switch m.confirmAction {
			case "save-edit", "discard-edit":
				m.view = viewEdit
			case "bin-overwrite":
				m.view = viewBinName
			case "dup-overwrite":
				m.view = viewDup
			default:
				m.view = viewTree
			}
			return m, nil
		}

		switch m.confirmAction {
		case "delete":
			if err := m.store.Remove(m.confirmTarget); err != nil {
				m.status = "delete failed: " + err.Error()
			} else {
				m.status = "deleted " + m.confirmTarget
			}
			m.closeEntry()
			m.rebuildTree()
			m.view = viewTree
		case "delete-dir":
			if err := m.store.RemoveDir(m.confirmTarget); err != nil {
				m.status = "delete failed: " + err.Error()
			} else {
				m.status = "deleted directory " + m.confirmTarget
			}
			m.rebuildTree()
			m.view = viewTree
		case "save-edit":
			m.saveEditor()
		case "discard-edit":
			m.status = "changes discarded"
			m.closeEditor(false)
		case "bin-overwrite":
			cmd := m.attachCmd(m.binFile, m.binName)
			m.view = m.binFrom
			return m, cmd
		case "dup-overwrite":
			m.dupApply()
		}
		return m, nil

	case m.km.Back:
		switch m.confirmAction {
		case "save-edit", "discard-edit":
			m.view = viewEdit
		case "bin-overwrite":
			m.view = viewBinName
		case "dup-overwrite":
			m.view = viewDup
		case "delete", "delete-dir":
			// Escape goes back where the action came from; declining
			// (above) keeps the historical return-to-tree.
			if m.confirmFrom == viewTree {
				m.view = viewTree
			} else {
				m.view = viewDetail
			}
		default:
			m.view = viewDetail
		}
		return m, nil
	}
	return m, nil
}

func (m Model) viewConfirm() string {
	var b strings.Builder
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "  %s %s?\n\n", m.st.confirm.Render(confirmLabel(m.confirmAction)+":"), m.st.bold.Render(m.confirmTarget))

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

// confirmLabel humanises the internal action name for the confirmation
// prompt.
func confirmLabel(action string) string {
	switch action {
	case "delete":
		return "delete"
	case "delete-dir":
		return "delete directory and all its entries"
	case "save-edit":
		return "save (overwrites password or deletes lines)"
	case "discard-edit":
		return "discard unsaved changes"
	case "bin-overwrite":
		return "overwrite the existing binary entry"
	case "dup-overwrite":
		return "overwrite the existing entry with the copy"
	}
	return action
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
		return m, m.generateCmd(m.genLength, m.genSymbols)

	case "+", "=": // longer, with a live preview
		if m.genLength < pwgenMaxLen {
			m.genLength++
			return m, m.generateCmd(m.genLength, m.genSymbols)
		}
	case "-":
		if m.genLength > pwgenMinLen {
			m.genLength--
			return m, m.generateCmd(m.genLength, m.genSymbols)
		}
	case "s": // toggle the symbol alphabet
		m.genSymbols = !m.genSymbols
		return m, m.generateCmd(m.genLength, m.genSymbols)

	case m.km.Back:
		m.view = viewDetail
		return m, nil
	}
	return m, nil
}

// pwgen length bounds: pwgen itself has no hard floor, but a 1-character
// password from a slipped keypress is never what the user wanted.
const (
	pwgenMinLen = 4
	pwgenMaxLen = 128
)

func (m Model) viewGenerate() string {
	var b strings.Builder
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "  %s %s\n", m.st.header.Render("generate:"), m.st.bold.Render(m.genTarget))
	if m.genPreview != "" {
		fmt.Fprintf(&b, "  %s %s\n", m.st.dimmed.Render("new:"), m.st.visible.Render(m.genPreview))
	} else {
		fmt.Fprintln(&b, m.st.dimmed.Render("  generating..."))
	}
	sym := "symbols"
	if !m.genSymbols {
		sym = "no symbols"
	}
	fmt.Fprintf(&b, "  %s %d   %s\n", m.st.dimmed.Render("length:"), m.genLength, m.st.dimmed.Render("("+sym+")"))
	fmt.Fprintf(&b, "\n  %s\n", m.st.dimmed.Render("enter:apply  r:regenerate  +/-:length  s:symbols  esc:cancel"))
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
			if m.insertLen == 0 {
				m.insertLen = m.cfg.GeneratedLength
			}
			return m, m.insertGenerateCmd(m.insertLen, m.insertSymbols)

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

	case 1: // password: generated or hand-typed
		switch msg.String() {
		case "enter":
			if m.insertPassword == "" {
				m.status = "insert: password is empty"
				return m, nil
			}
			// Create the entry with the password right away — the
			// same contract `insert` gives — then open the editor so
			// fields and notes can be added before the user moves on.
			sec := secret.New(m.insertPassword, "")
			if err := m.store.Set(m.insertName, sec); err != nil {
				m.status = "insert: " + err.Error()
				return m, nil
			}
			m.status = "created " + m.insertName
			m.rebuildTree()
			m.current = m.insertName
			m.sec = sec
			m.startEdit()
			return m, nil

		case "ctrl+g": // toggle generator/manual
			// A printable key cannot own this: in manual mode every
			// printable rune belongs to the password being typed.
			m.insertManual = !m.insertManual
			if m.insertManual {
				// A generated password must not silently masquerade
				// as something the user chose to type.
				m.insertPassword = ""
			} else {
				return m, m.insertGenerateCmd(m.insertLen, m.insertSymbols)
			}

		case m.km.Back:
			m.insertStep = 0 // back to name input

		default:
			switch s := msg.String(); {
			case !m.insertManual && s == "r":
				return m, m.insertGenerateCmd(m.insertLen, m.insertSymbols)
			case !m.insertManual && (s == "+" || s == "="):
				if m.insertLen < pwgenMaxLen {
					m.insertLen++
					return m, m.insertGenerateCmd(m.insertLen, m.insertSymbols)
				}
			case !m.insertManual && s == "-":
				if m.insertLen > pwgenMinLen {
					m.insertLen--
					return m, m.insertGenerateCmd(m.insertLen, m.insertSymbols)
				}
			case !m.insertManual && s == "s":
				m.insertSymbols = !m.insertSymbols
				return m, m.insertGenerateCmd(m.insertLen, m.insertSymbols)
			case m.insertManual:
				applyInputKey(&m.insertPassword, msg)
			}
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
		mode := "generated"
		if m.insertManual {
			mode = "manual"
		}
		fmt.Fprintf(&b, "  %s %s  %s\n", m.st.header.Render("new entry:"), m.st.bold.Render(m.insertName), m.st.dimmed.Render("("+mode+")"))
		if m.insertPassword != "" {
			fmt.Fprintf(&b, "  %s %s\n", m.st.dimmed.Render("pass:"), m.st.visible.Render(m.insertPassword))
		} else if m.insertManual {
			fmt.Fprintf(&b, "  %s %s\n", m.st.dimmed.Render("pass:"), m.st.visible.Render("")+"▏")
		} else {
			fmt.Fprintln(&b, m.st.dimmed.Render("  generating..."))
		}
		if m.insertManual {
			fmt.Fprintf(&b, "\n  %s\n", m.st.dimmed.Render("enter:create  ctrl+g:use generator  esc:back"))
		} else {
			sym := "symbols"
			if !m.insertSymbols {
				sym = "no symbols"
			}
			fmt.Fprintf(&b, "  %s %d   %s\n", m.st.dimmed.Render("length:"), m.insertLen, m.st.dimmed.Render("("+sym+")"))
			fmt.Fprintf(&b, "\n  %s\n", m.st.dimmed.Render("enter:create  r:regenerate  +/-:length  s:symbols  ctrl+g:type manually  esc:back"))
		}
	}

	return b.String()
}

// insertGenerateCmd returns a tea.Cmd that generates a password for the new entry.
func (m Model) insertGenerateCmd(length int, symbols bool) tea.Cmd {
	charset := m.genCharset(symbols)
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
			case viewFiles:
				if m.filesCur > 2 {
					m.filesCur -= 3
				} else {
					m.filesCur = 0
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
			case viewFiles:
				if m.filesCur < len(m.filesVis)-3 {
					m.filesCur += 3
				} else {
					m.filesCur = len(m.filesVis) - 1
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
	m.binBackdrop = binary.IsBinary(name)
	m.binSize = 0
	m.binSum = ""
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
	m.binBackdrop = false
	m.binSize = 0
	m.binSum = ""
}

// initBinary computes the display metadata of a decrypted binary entry.
// Like initOTP it runs on the async unlock result, keeping the multi-meg
// base64 decode off the key path.
func (m *Model) initBinary() {
	if !m.binBackdrop || m.sec == nil {
		return
	}
	m.binSize, m.binSum = binStats(m.sec)
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
func (m Model) generateCmd(length int, symbols bool) tea.Cmd {
	charset := m.genCharset(symbols)
	return func() tea.Msg {
		pw, err := pwgen.Generate(length, charset)
		return generateResult{password: pw, err: err}
	}
}

// genCharset picks the generation alphabet. The no-symbols alphabet
// matches the CLI's --no-symbols setting, so a password copied out of the
// TUI obeys the same policy as one from `generate`.
func (m Model) genCharset(symbols bool) string {
	if symbols {
		return m.cfg.CharacterSet
	}
	return m.cfg.CharacterSetNoSymbols
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
	return m.copyValueCmd(m.current, m.sec.Password())
}

// copyOTPCodeCmd returns a tea.Cmd that copies the current OTP code.
func (m Model) copyOTPCodeCmd() tea.Cmd {
	return m.copyValueCmd("OTP code", m.otpCode)
}

// lock clears all decrypted secrets from memory, including any staged
// editor copy — it is plaintext just like the open entry.
func (m *Model) lock() {
	m.locked = true
	m.sec = nil
	m.editor = nil
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
	// Walk runes, not bytes: a prefix cut mid-rune is invalid UTF-8, and
	// how much width such a prefix has is undefined — exactly what bit
	// when the width library started counting invalid bytes instead of
	// ignoring them.
	var b strings.Builder
	cells := 0
	for _, r := range s {
		w := lipgloss.Width(string(r))
		if cells+w > maxCells {
			break
		}
		b.WriteRune(r)
		cells += w
	}
	return b.String()
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
