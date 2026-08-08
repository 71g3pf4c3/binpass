package clip

import (
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
)

// tool is a clipboard backend driven by an external command.
type tool struct {
	// name identifies the backend.
	name string
	// bin is the executable to look for on PATH.
	bin string
	// copyArgs are the arguments that write stdin to the clipboard.
	copyArgs []string
	// pasteArgs are the arguments that print the clipboard to stdout.
	pasteArgs []string
	// requiresEnv, when set, must be present in the environment for this
	// backend to be considered: wl-copy on X11 would fail at runtime.
	requiresEnv string
}

// Name returns the backend name.
func (t *tool) Name() string { return t.name }

// Available reports whether the tool is installed and its session type active.
func (t *tool) Available() bool {
	if t.requiresEnv != "" && os.Getenv(t.requiresEnv) == "" {
		return false
	}
	_, err := exec.LookPath(t.bin)
	return err == nil
}

// Copy writes text to the clipboard.
func (t *tool) Copy(ctx context.Context, text string) error {
	_, err := run(ctx, t.bin, t.copyArgs, text)
	return err
}

// Paste reads the clipboard.
func (t *tool) Paste(ctx context.Context) (string, error) {
	return run(ctx, t.bin, t.pasteArgs, "")
}

// backends returns the candidate backends in priority order: the native
// session protocol first, then the X11 fallback.
func backends(selection string) []Backend {
	if selection == "" {
		selection = "clipboard"
	}
	return []Backend{
		&tool{
			name:        "wl-clipboard",
			bin:         "wl-copy",
			copyArgs:    wlCopyArgs(selection),
			pasteArgs:   nil,
			requiresEnv: "WAYLAND_DISPLAY",
		},
		&wlPaste{selection: selection},
		&tool{
			name:        "xclip",
			bin:         "xclip",
			copyArgs:    []string{"-selection", selection, "-in"},
			pasteArgs:   []string{"-selection", selection, "-out"},
			requiresEnv: "DISPLAY",
		},
		&tool{
			name:      "pbcopy",
			bin:       "pbcopy",
			copyArgs:  nil,
			pasteArgs: nil,
		},
	}
}

// wlCopyArgs maps an X selection name onto wl-copy's flags.
func wlCopyArgs(selection string) []string {
	if selection == "primary" {
		return []string{"--primary"}
	}
	return nil
}

// wlPaste pairs wl-copy for writing with wl-paste for reading, since the two
// halves live in different binaries.
type wlPaste struct {
	// selection is the X selection name to emulate.
	selection string
}

// Name returns the backend name.
func (w *wlPaste) Name() string { return "wl-clipboard" }

// Available reports whether both halves of wl-clipboard are present.
func (w *wlPaste) Available() bool {
	if os.Getenv("WAYLAND_DISPLAY") == "" {
		return false
	}
	if _, err := exec.LookPath("wl-copy"); err != nil {
		return false
	}
	_, err := exec.LookPath("wl-paste")
	return err == nil
}

// Copy writes text to the Wayland clipboard.
func (w *wlPaste) Copy(ctx context.Context, text string) error {
	_, err := run(ctx, "wl-copy", wlCopyArgs(w.selection), text)
	return err
}

// Paste reads the Wayland clipboard, without the trailing newline wl-paste
// appends.
func (w *wlPaste) Paste(ctx context.Context) (string, error) {
	args := []string{"--no-newline"}
	if w.selection == "primary" {
		args = append(args, "--primary")
	}
	return run(ctx, "wl-paste", args, "")
}

// stringReader adapts a string to an io.Reader for command stdin.
func stringReader(s string) io.Reader { return strings.NewReader(s) }
