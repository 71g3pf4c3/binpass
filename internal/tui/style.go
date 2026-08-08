package tui

import "github.com/charmbracelet/lipgloss"

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

// newStyles builds the style set, disabling colour when the environment
// requests it.
func newStyles(noColor bool) styles {
	if noColor {
		s := styles{noColor: true}
		s.selected = lipgloss.NewStyle().Bold(true)
		s.bold = lipgloss.NewStyle().Bold(true)
		return s
	}

	s := styles{}

	s.branch = lipgloss.NewStyle().
		Foreground(lipgloss.Color("12")). // bright blue
		Bold(true)

	s.leaf = lipgloss.NewStyle().
		Foreground(lipgloss.Color("15")) // white

	s.selected = lipgloss.NewStyle().
		Foreground(lipgloss.Color("230")). // cornsilk1
		Background(lipgloss.Color("62")).  // steel blue
		Bold(true)

	s.dimmed = lipgloss.NewStyle().
		Foreground(lipgloss.Color("245")) // grey58

	s.bold = lipgloss.NewStyle().Bold(true)

	s.header = lipgloss.NewStyle().
		Foreground(lipgloss.Color("86")). // aquamarine1
		Bold(true)

	s.errorMsg = lipgloss.NewStyle().
		Foreground(lipgloss.Color("196")). // red1
		Bold(true)

	s.masked = lipgloss.NewStyle().
		Foreground(lipgloss.Color("245")) // grey58

	s.visible = lipgloss.NewStyle().
		Foreground(lipgloss.Color("46")). // spring green
		Bold(true)

	s.otpCode = lipgloss.NewStyle().
		Foreground(lipgloss.Color("220")). // gold1
		Bold(true)

	s.otpTimer = lipgloss.NewStyle().
		Foreground(lipgloss.Color("208")) // dark orange

	s.search = lipgloss.NewStyle().
		Foreground(lipgloss.Color("214")). // orange1
		Bold(true)

	s.confirm = lipgloss.NewStyle().
		Foreground(lipgloss.Color("196")). // red1
		Bold(true)

	s.border = lipgloss.NewStyle().
		BorderForeground(lipgloss.Color("62")) // steel blue

	s.statusBar = lipgloss.NewStyle().
		Foreground(lipgloss.Color("252")). // grey78
		Background(lipgloss.Color("236"))  // dark grey

	return s
}
