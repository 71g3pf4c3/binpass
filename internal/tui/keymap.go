// Package tui implements the interactive terminal interface for binpass,
// built on charmbracelet/bubbletea. It provides a persistent session for
// browsing, searching, and managing the password store — as opposed to
// binpass menu, which is a one-shot picker.
//
// Secrets are only decrypted when an entry is opened (lazy decryption),
// so navigating a store backed by a hardware token does not trigger
// repeated touch prompts.
package tui

// Key bindings for the TUI. Grouped by view so that the same key can serve
// different roles in different contexts without collision.
type keymap struct {
	// Tree view.
	Up       string
	Down     string
	Enter    string
	Collapse string
	Search   string
	Quit     string
	NewEntry string

	// Detail view.
	TogglePassword string
	CopyPassword   string
	CopyOTP        string
	Delete         string
	Rename         string
	Back           string
	Generate       string
	History        string

	// Search view.
	ClearSearch string
}

// defaultKeymap returns the standard key bindings.
func defaultKeymap() keymap {
	return keymap{
		Up:             "up",
		Down:           "down",
		Enter:          "enter",
		Collapse:       "h",
		Search:         "/",
		Quit:           "q",
		NewEntry:       "n",
		TogglePassword: "p",
		CopyPassword:   "c",
		CopyOTP:        "o",
		Delete:         "d",
		Rename:         "r",
		Back:           "esc",
		Generate:       "g",
		History:        "y",
		ClearSearch:    "esc",
	}
}
