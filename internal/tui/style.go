package tui

import (
	"github.com/71g3pf4c3/binpass/internal/theme"
	"github.com/charmbracelet/lipgloss"
)

// Styles centralises the visual presentation so that NO_COLOR and narrow
// terminals degrade gracefully. When noColor is true every style becomes a
// no-op, which matches the ECMA-48 intent of the NO_COLOR convention.
type styles struct {
	noColor bool

	branch    lipgloss.Style
	leaf      lipgloss.Style
	selected  lipgloss.Style
	dimmed    lipgloss.Style
	bold      lipgloss.Style
	header    lipgloss.Style
	errorMsg  lipgloss.Style
	masked    lipgloss.Style
	visible   lipgloss.Style
	otpCode   lipgloss.Style
	otpTimer  lipgloss.Style
	search    lipgloss.Style
	confirm   lipgloss.Style
	border    lipgloss.Style
	statusBar lipgloss.Style
}

// newStyles builds the style set from a theme palette, disabling colour
// when the environment requests it. NO_COLOR wins over any theme: the
// palette only chooses colours, never whether to emit them.
func newStyles(noColor bool, p theme.Palette) styles {
	if noColor {
		s := styles{noColor: true}
		s.selected = lipgloss.NewStyle().Bold(true)
		s.bold = lipgloss.NewStyle().Bold(true)
		return s
	}

	s := styles{}

	s.branch = lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.Branch)).
		Bold(true)

	s.leaf = lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.Leaf))

	s.selected = lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.SelectedFg)).
		Background(lipgloss.Color(p.SelectedBg)).
		Bold(true)

	s.dimmed = lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.Dimmed))

	s.bold = lipgloss.NewStyle().Bold(true)

	s.header = lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.Header)).
		Bold(true)

	s.errorMsg = lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.Error)).
		Bold(true)

	s.masked = lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.Dimmed))

	s.visible = lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.Visible)).
		Bold(true)

	s.otpCode = lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.OTPCode)).
		Bold(true)

	s.otpTimer = lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.OTPTimer))

	s.search = lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.Search)).
		Bold(true)

	s.confirm = lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.Confirm)).
		Bold(true)

	s.border = lipgloss.NewStyle().
		BorderForeground(lipgloss.Color(p.Border))

	s.statusBar = lipgloss.NewStyle().
		Foreground(lipgloss.Color(p.StatusFg)).
		Background(lipgloss.Color(p.StatusBg))

	return s
}
