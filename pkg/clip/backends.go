package clip

import (
	"context"
	"os"
	"os/exec"
)

// tool is a clipboard backend driven by external commands.
//
// Reading and writing may be different executables (pbpaste and pbcopy), so
// both are named explicitly. Sharing one field caused wl-copy to be invoked
// as a paste, which wiped the clipboard instead of reading it.
type tool struct {
	// name identifies the backend.
	name string
	// bin is the executable that reads the clipboard.
	bin string
	// copyBin is the executable that writes the clipboard.
	copyBin string
	// copyArgs are the arguments that write stdin to the clipboard.
	copyArgs []string
	// pasteArgs are the arguments that print the clipboard to stdout.
	pasteArgs []string
	// requiresEnv, when set, must be present in the environment for this
	// backend to be considered: xclip without a DISPLAY fails at runtime.
	requiresEnv string
}

// Name returns the backend name.
func (t *tool) Name() string { return t.name }

// Available reports whether both halves are installed and the session is right.
func (t *tool) Available() bool {
	if t.requiresEnv != "" && os.Getenv(t.requiresEnv) == "" {
		return false
	}
	if _, err := exec.LookPath(t.bin); err != nil {
		return false
	}
	_, err := exec.LookPath(t.copyBin)
	return err == nil
}

// Copy writes text to the clipboard.
func (t *tool) Copy(ctx context.Context, text string) error {
	return runCopy(ctx, t.copyBin, t.copyArgs, text)
}

// Paste reads the clipboard.
func (t *tool) Paste(ctx context.Context) (string, error) {
	return run(ctx, t.bin, t.pasteArgs)
}

// backends returns the candidate backends in priority order: the native
// session protocol first, then the X11 fallback.
func backends(selection string) []Backend {
	if selection == "" {
		selection = "clipboard"
	}
	return []Backend{
		// Wayland first: a session may export DISPLAY as well through
		// Xwayland, and driving the X11 clipboard there only writes to a
		// compatibility layer.
		&wlClipboard{selection: selection},
		&tool{
			name:        "xclip",
			bin:         "xclip",
			copyBin:     "xclip",
			copyArgs:    []string{"-selection", selection, "-in"},
			pasteArgs:   []string{"-selection", selection, "-out"},
			requiresEnv: "DISPLAY",
		},
		&tool{
			name:      "xsel",
			bin:       "xsel",
			copyBin:   "xsel",
			copyArgs:  []string{"--" + selection, "--input"},
			pasteArgs: []string{"--" + selection, "--output"},

			requiresEnv: "DISPLAY",
		},
		&tool{
			name:      "pbcopy",
			bin:       "pbpaste",
			copyBin:   "pbcopy",
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

// wlClipboard drives wl-clipboard, whose two halves live in separate
// binaries: wl-copy writes and wl-paste reads.
type wlClipboard struct {
	// selection is the X selection name to emulate.
	selection string
}

// Name returns the backend name.
func (w *wlClipboard) Name() string { return "wl-clipboard" }

// Available reports whether both halves of wl-clipboard are present.
func (w *wlClipboard) Available() bool {
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
func (w *wlClipboard) Copy(ctx context.Context, text string) error {
	return runCopy(ctx, "wl-copy", wlCopyArgs(w.selection), text)
}

// Paste reads the Wayland clipboard, without the trailing newline wl-paste
// appends. An empty clipboard makes wl-paste exit non-zero, which is a normal
// state rather than a failure.
func (w *wlClipboard) Paste(ctx context.Context) (string, error) {
	args := []string{"--no-newline"}
	if w.selection == "primary" {
		args = append(args, "--primary")
	}
	out, err := run(ctx, "wl-paste", args)
	if err != nil {
		return "", nil //nolint:nilerr // an empty clipboard is not an error.
	}
	return out, nil
}

// BackendReport explains one clipboard backend's state in this session: why
// Detect would or would not reach it. It carries no state of its own beyond
// what Available computes, so it can never disagree with a Detect call made
// in the same moment.
type BackendReport struct {
	// Name identifies the backend.
	Name string
	// Available reports whether the backend can run here.
	Available bool
	// Missing lists what keeps the backend down: unset session variables
	// and binaries absent from PATH. It is empty when Available is set.
	Missing []string
}

// Reports describes every backend for selection in priority order. The
// first Available entry is the one Detect returns, so a diagnostician can
// name the winner and explain the losers without duplicating the
// detection logic.
func Reports(selection string) []BackendReport {
	out := make([]BackendReport, 0)
	for _, b := range backends(selection) {
		r := BackendReport{Name: b.Name(), Available: b.Available()}
		if !r.Available {
			switch v := b.(type) {
			case *wlClipboard:
				r.Missing = wlMissing()
			case *tool:
				r.Missing = v.missing()
			}
		}
		out = append(out, r)
	}
	return out
}

// wlMissing names what keeps the wl-clipboard backend down. The reasons are
// collected separately from Available because Available only answers yes or
// no, while a doctor has to say what to fix.
func wlMissing() []string {
	var m []string
	if os.Getenv("WAYLAND_DISPLAY") == "" {
		m = append(m, "WAYLAND_DISPLAY not set")
	}
	if _, err := exec.LookPath("wl-copy"); err != nil {
		m = append(m, "wl-copy not on PATH")
	}
	if _, err := exec.LookPath("wl-paste"); err != nil {
		m = append(m, "wl-paste not on PATH")
	}
	return m
}

// missing names what keeps a command backend down, in the order Available
// checks them: session first, then binaries. A backend whose read and
// write halves are one binary reports it once.
func (t *tool) missing() []string {
	var m []string
	if t.requiresEnv != "" && os.Getenv(t.requiresEnv) == "" {
		m = append(m, t.requiresEnv+" not set")
	}
	if _, err := exec.LookPath(t.bin); err != nil {
		m = append(m, t.bin+" not on PATH")
	}
	if t.copyBin != t.bin {
		if _, err := exec.LookPath(t.copyBin); err != nil {
			m = append(m, t.copyBin+" not on PATH")
		}
	}
	return m
}
