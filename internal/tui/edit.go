package tui

import (
	"fmt"
	"strings"

	"github.com/71g3pf4c3/binpass/pkg/secret"
	tea "github.com/charmbracelet/bubbletea"
)

// editRowKind distinguishes the editable line types of a secret's body.
type editRowKind int

const (
	// rowField is a "key: value" line.
	rowField editRowKind = iota
	// rowNote is any other line, including otpauth:// URIs.
	rowNote
)

// editRow is one staged, editable line of the entry body.
type editRow struct {
	kind  editRowKind
	key   string
	value string
	otp   bool
}

// text renders the row back to its on-disk line.
func (r editRow) text() string {
	if r.kind == rowField {
		return r.key + ": " + r.value
	}
	return r.value
}

// entryEditor stages changes to a secret before they are written back to
// the store. It models the entry the way pass stores it — a password line
// plus an ordered list of body lines — so that unchanged lines keep their
// position and the serialised result is exactly the format pass round-trips.
// All operations are pure in-memory mutations; nothing touches the store
// until Apply, which makes the whole editor table-drivable in tests.
type entryEditor struct {
	// password is the staged first line.
	password string
	// origPassword is the password as loaded, for the dirty check.
	origPassword string
	// rows are the staged body lines in order.
	rows []editRow
	// origRows is the body as loaded, for the dirty check.
	origRows []editRow
	// removed counts rows deleted since load. A deletion is destructive:
	// its bytes are gone from the staged copy and only a re-type brings
	// them back, so the save gate asks for confirmation when removed > 0.
	removed int
}

// newEntryEditor loads the secret into an editable staging area.
func newEntryEditor(sec *secret.Secret) *entryEditor {
	e := &entryEditor{
		origPassword: sec.Password(),
		origRows:     bodyRows(sec),
	}
	e.password = e.origPassword
	e.rows = make([]editRow, len(e.origRows))
	copy(e.rows, e.origRows)
	return e
}

// bodyRows interprets the lines after the password: "key: value" lines
// become field rows, everything else (including otpauth:// URIs) becomes a
// note row. The original line is preserved verbatim in the note value, so
// unedited lines round-trip byte for byte.
func bodyRows(sec *secret.Secret) []editRow {
	lines := sec.Lines()
	if len(lines) < 2 {
		return nil
	}
	rows := make([]editRow, 0, len(lines)-1)
	for _, line := range lines[1:] {
		if strings.HasPrefix(line, "otpauth://") {
			rows = append(rows, editRow{kind: rowNote, value: line, otp: true})
			continue
		}
		if k, v, ok := splitField(line); ok {
			rows = append(rows, editRow{kind: rowField, key: k, value: v})
			continue
		}
		rows = append(rows, editRow{kind: rowNote, value: line})
	}
	return rows
}

// dirty reports whether the staged copy differs from what was loaded.
func (e *entryEditor) dirty() bool {
	if e.password != e.origPassword || e.removed > 0 {
		return true
	}
	if len(e.rows) != len(e.origRows) {
		return true
	}
	for i := range e.rows {
		if e.rows[i] != e.origRows[i] {
			return true
		}
	}
	return false
}

// destructive reports whether saving would remove information the entry
// currently holds: a replaced password or deleted lines. Value edits and
// additions never lose bytes and are applied without a prompt.
func (e *entryEditor) destructive() bool {
	return e.password != e.origPassword || e.removed > 0
}

// apply builds the new secret from the staged state.
func (e *entryEditor) apply() *secret.Secret {
	lines := make([]string, 0, len(e.rows)+1)
	for _, r := range e.rows {
		lines = append(lines, r.text())
	}
	return secret.New(e.password, strings.Join(lines, "\n"))
}

// setPassword replaces the staged password line.
func (e *entryEditor) setPassword(pw string) { e.password = pw }

// setValue replaces the staged value of row i (or the password when i is
// the virtual row -1).
func (e *entryEditor) setValue(i int, v string) {
	if i == -1 {
		e.password = v
		return
	}
	e.rows[i].value = v
}

// setKey renames the key of field row i. The key must obey the same rules
// the parser applies: non-empty, no whitespace, so the line keeps parsing
// as a field after the rename.
func (e *entryEditor) setKey(i int, k string) { e.rows[i].key = k }

// addField appends a "key: value" row.
func (e *entryEditor) addField(k, v string) {
	e.rows = append(e.rows, editRow{kind: rowField, key: k, value: v})
}

// addNote appends a free-form line.
func (e *entryEditor) addNote(text string) {
	otp := strings.HasPrefix(text, "otpauth://")
	e.rows = append(e.rows, editRow{kind: rowNote, value: text, otp: otp})
}

// deleteRow removes row i from the staged copy. Deleting the password line
// is not possible: the pass format always has one, and an empty password is
// expressed as an empty string, not a missing line.
func (e *entryEditor) deleteRow(i int) {
	if i < 0 || i >= len(e.rows) {
		return
	}
	e.rows = append(e.rows[:i], e.rows[i+1:]...)
	e.removed++
}

// rowCount is the number of selectable rows, including the virtual
// password row at index 0.
func (e *entryEditor) rowCount() int { return len(e.rows) + 1 }

// validFieldKey mirrors secret.splitField's rules so a renamed or newly
// added key cannot silently turn its line back into a note.
func validFieldKey(k string) bool {
	if k == "" || strings.ContainsAny(k, " \t") {
		return false
	}
	return !strings.Contains(k, ":")
}

// --- view: edit ---

// Edit view input modes: which question the bottom input line answers.
const (
	editBrowse   int = iota // navigating rows
	editValue               // editing the selected row's value or the password
	editKey                 // renaming the selected field's key
	editNewKey              // typing the key of a new field
	editNewValue            // typing the value of a new field
	editNewNote             // typing a new free-form line
)

// startEdit opens the editor on the currently displayed entry. The entry
// must already be decrypted: the editor stages a copy of the plaintext, so
// there is nothing to decrypt lazily here.
func (m *Model) startEdit() {
	m.editor = newEntryEditor(m.sec)
	m.editCur = 0
	m.editMode = editBrowse
	m.editName = m.current
	m.editNew = false
	m.view = viewEdit
}

// handleEdit dispatches keys for the entry editor view.
func (m Model) handleEdit(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.editor == nil { // unreachable unless state was corrupted; bail out.
		m.view = viewDetail
		return m, nil
	}

	if m.editMode != editBrowse {
		return m.handleEditInput(msg)
	}

	switch msg.String() {
	case m.km.Quit, "ctrl+c":
		return m, tea.Quit

	case m.km.Up, "k":
		if m.editCur > 0 {
			m.editCur--
		}
	case m.km.Down, "j":
		if m.editCur < m.editor.rowCount()-1 {
			m.editCur++
		}

	case m.km.Enter, "e":
		m.editMode = editValue
		if m.editCur == 0 {
			m.editInput = m.editor.password
		} else {
			m.editInput = m.editor.rows[m.editCur-1].value
		}

	case "K": // shift+k renames a field key; plain k stays navigation.
		if m.editCur > 0 && m.editor.rows[m.editCur-1].kind == rowField {
			m.editMode = editKey
			m.editInput = m.editor.rows[m.editCur-1].key
		}

	case "a":
		m.editMode = editNewKey
		m.editInput = ""

	case "A":
		m.editMode = editNewNote
		m.editInput = ""

	case "x", "d": // d mirrors the detail view's delete key.
		if m.editCur > 0 {
			m.editor.deleteRow(m.editCur - 1)
			if m.editCur > m.editor.rowCount()-1 {
				m.editCur = m.editor.rowCount() - 1
			}
		}

	case m.km.TogglePassword:
		m.showPass = !m.showPass

	case "S", "ctrl+s":
		if !m.editor.dirty() {
			m.status = "no changes"
			m.closeEditor(false)
			return m, nil
		}
		if m.editor.destructive() {
			m.confirmAction = "save-edit"
			m.confirmTarget = m.editName
			m.confirmFocus = 1 // default to "no" — destructive gate.
			m.view = viewConfirm
			return m, nil
		}
		m.saveEditor()

	case m.km.Back:
		if m.editor.dirty() {
			m.confirmAction = "discard-edit"
			m.confirmTarget = m.editName
			m.confirmFocus = 1
			m.view = viewConfirm
			return m, nil
		}
		m.closeEditor(false)
	}
	return m, nil
}

// handleEditInput dispatches keys while the bottom input line is active.
func (m Model) handleEditInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case m.km.Back:
		m.editMode = editBrowse

	case "enter":
		mode, input := m.editMode, m.editInput
		m.editMode = editBrowse
		switch mode {
		case editValue:
			m.editor.setValue(m.editCur-1, input)
		case editKey:
			if !validFieldKey(input) {
				m.status = "key must be non-empty, without spaces or colons"
			} else {
				m.editor.setKey(m.editCur-1, input)
			}
		case editNewKey:
			if !validFieldKey(input) {
				m.status = "key must be non-empty, without spaces or colons"
				m.editMode = editNewKey
			} else {
				m.editKey = input
				m.editMode = editNewValue
				m.editInput = ""
			}
		case editNewValue:
			m.editor.addField(m.editKey, input)
			m.editCur = m.editor.rowCount() - 1
		case editNewNote:
			m.editor.addNote(input)
			m.editCur = m.editor.rowCount() - 1
		}

	default:
		applyInputKey(&m.editInput, msg)
	}
	return m, nil
}

// saveEditor writes the staged entry to the store and refreshes the detail
// view. A failed write keeps the editor open with the staged copy intact,
// so nothing the user typed is lost.
func (m *Model) saveEditor() {
	sec := m.editor.apply()
	if err := m.store.Set(m.editName, sec); err != nil {
		m.status = "edit: " + err.Error()
		m.view = viewEdit // stay in the editor when the store refused.
		return
	}
	if m.editNew {
		m.status = "created " + m.editName
		m.rebuildTree()
		m.closeEditor(true)
		return
	}
	m.status = "saved " + m.editName
	m.sec = sec
	m.initOTP() // the otpauth line may have been added, changed or removed.
	m.closeEditor(false)
}

// closeEditor leaves the editor, clearing the staged plaintext. When the
// editor created a new entry there is no detail view to return to.
func (m *Model) closeEditor(created bool) {
	m.editor = nil
	m.editInput = ""
	m.editMode = editBrowse
	if created || m.editNew {
		m.view = viewTree
		return
	}
	m.view = viewDetail
}

// viewEdit renders the entry editor.
func (m Model) viewEdit() string {
	if m.editor == nil {
		return ""
	}
	var b strings.Builder

	dirty := ""
	if m.editor.dirty() {
		dirty = " ●"
	}
	fmt.Fprintf(&b, "  %s %s%s\n\n", m.st.header.Render("edit:"), m.st.bold.Render(m.editName), m.st.dimmed.Render(dirty))

	// Password row (virtual row 0).
	pw := m.editor.password
	if !m.showPass {
		pw = maskPassword(pw)
	}
	m.renderEditRow(&b, 0, m.st.dimmed.Render("pass:")+" "+pw)

	for i, r := range m.editor.rows {
		var line string
		switch {
		case r.kind == rowField:
			line = m.st.dimmed.Render(r.key+":") + " " + r.value
		case r.otp:
			line = m.st.dimmed.Render("otp:") + " " + r.value
		default:
			line = r.value
		}
		m.renderEditRow(&b, i+1, line)
	}

	// Input line, mirroring the selected row's width so the layout does
	// not jump between modes.
	if m.editMode != editBrowse {
		fmt.Fprintln(&b)
		fmt.Fprintf(&b, "  %s %s\n", m.st.dimmed.Render(editPrompt(m.editMode)+":"),
			m.st.visible.Render(m.editInput)+"▏")
	}

	bar := m.statusBar("enter:edit  a:add field  A:add note  x:del  K:rename key  p:toggle  S:save  esc:back")
	return b.String() + bar
}

// renderEditRow prints one editor row, highlighted when selected.
func (m Model) renderEditRow(b *strings.Builder, idx int, line string) {
	line = truncate("  "+line, m.width)
	if idx == m.editCur && m.editMode == editBrowse {
		fmt.Fprintf(b, "%s\n", m.st.selected.Render(line))
	} else {
		fmt.Fprintf(b, "%s\n", line)
	}
}

// editPrompt labels the input line for the current input mode.
func editPrompt(mode int) string {
	switch mode {
	case editValue:
		return "value"
	case editKey, editNewKey:
		return "key"
	case editNewValue:
		return "value"
	case editNewNote:
		return "note"
	}
	return ""
}

// applyInputKey applies plain editing keys to an input-line buffer. Keys
// with line semantics (backspace, ctrl+u, printable runes) mutate the
// buffer; anything else is ignored so view-level keys keep working.
func applyInputKey(buf *string, msg tea.KeyMsg) {
	switch msg.String() {
	case "backspace", "ctrl+h":
		r := []rune(*buf)
		if len(r) > 0 {
			*buf = string(r[:len(r)-1])
		}
	case "ctrl+u":
		*buf = ""
	case "ctrl+w":
		r := []rune(*buf)
		for len(r) > 0 && r[len(r)-1] == ' ' {
			r = r[:len(r)-1]
		}
		if i := strings.LastIndex(string(r), " "); i >= 0 {
			*buf = string(r[:i+1])
		} else {
			*buf = ""
		}
	default:
		runes := []rune(msg.String())
		if len(runes) == 1 && isPrintable(runes[0]) {
			*buf += string(runes[0])
		}
	}
}
