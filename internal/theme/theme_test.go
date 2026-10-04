package theme

import (
	"slices"
	"testing"
)

// TestEveryPaletteIsComplete guards the registry against a palette added
// with a slot left empty: lipgloss would silently skip the empty colour and
// the role would render unstyled, which no test on styles would catch.
func TestEveryPaletteIsComplete(t *testing.T) {
	for _, name := range Names() {
		p := Get(name)
		for _, field := range []struct {
			role  string
			color string
		}{
			{"Branch", p.Branch},
			{"Leaf", p.Leaf},
			{"SelectedFg", p.SelectedFg},
			{"SelectedBg", p.SelectedBg},
			{"Dimmed", p.Dimmed},
			{"Header", p.Header},
			{"Error", p.Error},
			{"Visible", p.Visible},
			{"OTPCode", p.OTPCode},
			{"OTPTimer", p.OTPTimer},
			{"Search", p.Search},
			{"Confirm", p.Confirm},
			{"Border", p.Border},
			{"StatusFg", p.StatusFg},
			{"StatusBg", p.StatusBg},
		} {
			if field.color == "" {
				t.Errorf("theme %q: role %s is empty", name, field.role)
			}
		}
		if p.Name != name {
			t.Errorf("palette registered as %q reports Name %q", name, p.Name)
		}
	}
}

func TestNamesAreSortedAndKnown(t *testing.T) {
	got := Names()
	if !slices.IsSorted(got) {
		t.Errorf("Names() is not sorted: %v", got)
	}
	for _, want := range []string{DefaultName, "gruvbox", "gruvbox-light", "nord", "dracula"} {
		if !slices.Contains(got, want) {
			t.Errorf("Names() is missing %q", want)
		}
	}
}

func TestGetFallsBackToDefault(t *testing.T) {
	for _, name := range []string{"", "does-not-exist", "GRUVBOX"} {
		if got := Get(name); got.Name != DefaultName {
			t.Errorf("Get(%q) = %q, want fallback to %q", name, got.Name, DefaultName)
		}
	}
}

func TestValid(t *testing.T) {
	for name, valid := range map[string]bool{
		"default":       true,
		"gruvbox":       true,
		"gruvbox-light": true,
		"nord":          true,
		"dracula":       true,
		"":              false,
		"solarized":     false,
	} {
		if got := Valid(name); got != valid {
			t.Errorf("Valid(%q) = %v, want %v", name, got, valid)
		}
	}
}

func TestDefaultPaletteKeepsLegacyColours(t *testing.T) {
	p := Default()
	if p.Branch != "12" || p.SelectedBg != "62" || p.StatusBg != "236" {
		t.Errorf("default palette drifted from the shipped colours: %+v", p)
	}
}
