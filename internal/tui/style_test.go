package tui

import (
	"testing"

	"github.com/71g3pf4c3/binpass/internal/theme"
	"github.com/charmbracelet/lipgloss"
)

// fgOf returns the foreground colour stored on a style, failing the test
// when the style carries none. Going through the getters rather than
// rendered output keeps the check independent of the colour profile the
// test environment happens to detect.
func fgOf(t *testing.T, name string, s lipgloss.Style) lipgloss.Color {
	t.Helper()
	c, ok := s.GetForeground().(lipgloss.Color)
	if !ok {
		t.Fatalf("%s: no foreground colour set", name)
	}
	return c
}

// bgOf is fgOf for background colours.
func bgOf(t *testing.T, name string, s lipgloss.Style) lipgloss.Color {
	t.Helper()
	c, ok := s.GetBackground().(lipgloss.Color)
	if !ok {
		t.Fatalf("%s: no background colour set", name)
	}
	return c
}

// TestDefaultPaletteKeepsLegacyColours pins the default theme to the exact
// ANSI palette the TUI shipped with, so adopting theming changes nothing
// for users who never asked for it.
func TestDefaultPaletteKeepsLegacyColours(t *testing.T) {
	st := newStyles(false, theme.Default())

	for _, tt := range []struct {
		name string
		got  lipgloss.Color
		want lipgloss.Color
	}{
		{"branch fg", fgOf(t, "branch", st.branch), "12"},
		{"leaf fg", fgOf(t, "leaf", st.leaf), "15"},
		{"selected fg", fgOf(t, "selected", st.selected), "230"},
		{"selected bg", bgOf(t, "selected", st.selected), "62"},
		{"dimmed fg", fgOf(t, "dimmed", st.dimmed), "245"},
		{"masked fg", fgOf(t, "masked", st.masked), "245"},
		{"header fg", fgOf(t, "header", st.header), "86"},
		{"error fg", fgOf(t, "error", st.errorMsg), "196"},
		{"visible fg", fgOf(t, "visible", st.visible), "46"},
		{"otp code fg", fgOf(t, "otpCode", st.otpCode), "220"},
		{"otp timer fg", fgOf(t, "otpTimer", st.otpTimer), "208"},
		{"search fg", fgOf(t, "search", st.search), "214"},
		{"confirm fg", fgOf(t, "confirm", st.confirm), "196"},
		{"status fg", fgOf(t, "statusBar", st.statusBar), "252"},
		{"status bg", bgOf(t, "statusBar", st.statusBar), "236"},
	} {
		if tt.got != tt.want {
			t.Errorf("%s = %q, want %q", tt.name, tt.got, tt.want)
		}
	}
	// BorderForeground sets all four sides, so any one of them proves the
	// colour landed; lipgloss v1 exposes only per-side getters.
	if c, ok := st.border.GetBorderTopForeground().(lipgloss.Color); !ok || c != "62" {
		t.Errorf("border fg = %v, want 62", st.border.GetBorderTopForeground())
	}
}

// TestPaletteIsApplied verifies the styles carry the palette they were
// built from, not the default one.
func TestPaletteIsApplied(t *testing.T) {
	p := theme.Get("gruvbox")
	st := newStyles(false, p)

	if got := fgOf(t, "branch", st.branch); got != lipgloss.Color(p.Branch) {
		t.Errorf("branch fg = %q, want %q", got, p.Branch)
	}
	if got := bgOf(t, "selected", st.selected); got != lipgloss.Color(p.SelectedBg) {
		t.Errorf("selected bg = %q, want %q", got, p.SelectedBg)
	}
	if got := bgOf(t, "statusBar", st.statusBar); got != lipgloss.Color(p.StatusBg) {
		t.Errorf("status bg = %q, want %q", got, p.StatusBg)
	}
}

// TestNoColorDropsPalette keeps the NO_COLOR contract: no theme, however
// configured, may re-enable colour once the environment asked for none.
func TestNoColorDropsPalette(t *testing.T) {
	st := newStyles(true, theme.Get("gruvbox"))

	// lipgloss reports "no colour" as its exported NoColor sentinel, not nil.
	if _, ok := st.branch.GetForeground().(lipgloss.NoColor); !ok {
		t.Error("branch style must carry no colour under NO_COLOR")
	}
	if _, ok := st.statusBar.GetBackground().(lipgloss.NoColor); !ok {
		t.Error("status bar must carry no background under NO_COLOR")
	}
	if got := st.leaf.Render("entry"); got != "entry" {
		t.Errorf("leaf style renders %q, want plain %q", got, "entry")
	}
}
