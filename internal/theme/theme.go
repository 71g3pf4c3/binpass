// Package theme holds the colour palettes the TUI can be dressed in.
//
// A palette is plain colour strings — ANSI indices like "12" or hex values
// like "#83a598" — so that the config layer can validate theme names without
// depending on a terminal-styling library, and the TUI remains the only
// place that turns them into styles.
package theme

import (
	"slices"
	"strings"
)

// DefaultName is the theme used when none is configured. Its palette keeps
// the exact colours the TUI shipped with, so existing setups see no change.
const DefaultName = "default"

// Palette assigns a colour to every visual role the TUI draws. The colour
// format is whatever lipgloss accepts: an ANSI index ("12") or a hex value
// ("#83a598").
type Palette struct {
	// Name is the palette's registry key.
	Name string
	// Branch colours directories in the tree.
	Branch string
	// Leaf colours entries in the tree.
	Leaf string
	// SelectedFg and SelectedBg highlight the cursor row.
	SelectedFg string
	// SelectedBg is the cursor row's background.
	SelectedBg string
	// Dimmed de-emphasises hints, masked secrets and chrome.
	Dimmed string
	// Header colours pane titles.
	Header string
	// Error colours error messages.
	Error string
	// Visible colours a revealed password.
	Visible string
	// OTPCode colours a one-time password.
	OTPCode string
	// OTPTimer colours the one-time password countdown.
	OTPTimer string
	// Search colours the search prompt.
	Search string
	// Confirm colours destructive-action prompts.
	Confirm string
	// Border colours pane borders.
	Border string
	// StatusFg is the status bar foreground.
	StatusFg string
	// StatusBg is the status bar background.
	StatusBg string
}

// palettes is the theme registry, keyed by name.
var palettes = map[string]Palette{
	"default": {
		Name:       "default",
		Branch:     "12",  // bright blue
		Leaf:       "15",  // white
		SelectedFg: "230", // cornsilk1
		SelectedBg: "62",  // steel blue
		Dimmed:     "245", // grey58
		Header:     "86",  // aquamarine1
		Error:      "196", // red1
		Visible:    "46",  // spring green
		OTPCode:    "220", // gold1
		OTPTimer:   "208", // dark orange
		Search:     "214", // orange1
		Confirm:    "196", // red1
		Border:     "62",  // steel blue
		StatusFg:   "252", // grey78
		StatusBg:   "236", // dark grey
	},
	// https://github.com/morhetz/gruvbox (dark variant). The colours assume
	// the terminal itself runs a gruvbox dark background; on any other
	// background they still work, they just stop being the palette they
	// came from.
	"gruvbox": {
		Name:       "gruvbox",
		Branch:     "#83a598", // bright blue
		Leaf:       "#ebdbb2", // light1
		SelectedFg: "#1d2021", // dark0 hard
		SelectedBg: "#fabd2f", // bright yellow
		Dimmed:     "#a89984", // light4
		Header:     "#8ec07c", // bright aqua
		Error:      "#fb4934", // bright red
		Visible:    "#b8bb26", // bright green
		OTPCode:    "#fabd2f", // bright yellow
		OTPTimer:   "#fe8019", // bright orange
		Search:     "#fe8019", // bright orange
		Confirm:    "#fb4934", // bright red
		Border:     "#665c54", // dark3
		StatusFg:   "#ebdbb2", // light1
		StatusBg:   "#3c3836", // dark1
	},
	// https://github.com/morhetz/gruvbox (light variant).
	"gruvbox-light": {
		Name:       "gruvbox-light",
		Branch:     "#076678", // bright blue
		Leaf:       "#3c3836", // dark1
		SelectedFg: "#fbf1c7", // light0
		SelectedBg: "#b57614", // bright yellow
		Dimmed:     "#7c6f64", // dark4
		Header:     "#427b58", // bright aqua
		Error:      "#9d0006", // bright red
		Visible:    "#79740e", // bright green
		OTPCode:    "#b57614", // bright yellow
		OTPTimer:   "#af3a03", // bright orange
		Search:     "#af3a03", // bright orange
		Confirm:    "#9d0006", // bright red
		Border:     "#bdae93", // light3
		StatusFg:   "#3c3836", // dark1
		StatusBg:   "#d5c4a1", // light2
	},
	// https://www.nordtheme.com/docs/colors-and-palettes.
	"nord": {
		Name:       "nord",
		Branch:     "#81A1C1", // nord9
		Leaf:       "#ECEFF4", // nord6
		SelectedFg: "#2E3440", // nord0
		SelectedBg: "#EBCB8B", // nord13
		Dimmed:     "#4C566A", // nord3
		Header:     "#88C0D0", // nord8
		Error:      "#BF616A", // nord11
		Visible:    "#A3BE8C", // nord14
		OTPCode:    "#EBCB8B", // nord13
		OTPTimer:   "#D08770", // nord12
		Search:     "#B48EAD", // nord15
		Confirm:    "#BF616A", // nord11
		Border:     "#434C5E", // nord2
		StatusFg:   "#D8DEE9", // nord4
		StatusBg:   "#3B4252", // nord1
	},
	// https://draculatheme.com/palette.
	"dracula": {
		Name:       "dracula",
		Branch:     "#BD93F9", // purple
		Leaf:       "#F8F8F2", // foreground
		SelectedFg: "#282A36", // background
		SelectedBg: "#F1FA8C", // yellow
		Dimmed:     "#6272A4", // comment
		Header:     "#8BE9FD", // cyan
		Error:      "#FF5555", // red
		Visible:    "#50FA7B", // green
		OTPCode:    "#F1FA8C", // yellow
		OTPTimer:   "#FFB86C", // orange
		Search:     "#FFB86C", // orange
		Confirm:    "#FF5555", // red
		Border:     "#44475A", // current line
		StatusFg:   "#F8F8F2", // foreground
		StatusBg:   "#44475A", // current line
	},
}

// Default returns the palette used when no theme is configured.
func Default() Palette {
	return palettes[DefaultName]
}

// Get returns the named palette. An unknown name falls back to Default
// rather than erroring: the config file already rejects unknown names, so
// reaching here with one means an environment or flag value that was let
// through, and a password manager that still opens beats one that refuses.
func Get(name string) Palette {
	if p, ok := palettes[name]; ok {
		return p
	}
	return Default()
}

// Names returns the available theme names, sorted, for help text and
// completion.
func Names() []string {
	names := make([]string, 0, len(palettes))
	for name := range palettes {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// Valid reports whether name is a registered theme.
func Valid(name string) bool {
	_, ok := palettes[name]
	return ok
}

// String joins the theme names for use in help and error messages.
func String() string {
	return strings.Join(Names(), ", ")
}
