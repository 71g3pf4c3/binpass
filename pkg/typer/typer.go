// Package typer types secrets straight into the focused window, so a
// password reaches a form without ever touching the clipboard.
//
// The text is always fed on standard input, never as an argument: on a
// multi-user machine, ps(1) shows every process's command line to every
// user, and a secret typed as an argument would sit there for the
// process's lifetime.
package typer

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
)

// ErrNoTool reports that no typing tool is available in this session.
var ErrNoTool = errors.New("typer: no typing tool found; install wtype, ydotool or xdotool")

// tool describes one typing backend: the command to run and the session
// variable that must be set for it to work.
type tool struct {
	// bin is the executable to run.
	bin string
	// args is its fixed command line. The text is appended by stdin.
	args []string
	// needs names an environment variable the tool cannot work without:
	// wtype is Wayland-only, xdotool is X11-only. ydotool speaks uinput
	// and needs neither, which is why it runs last — it depends on a
	// daemon that LookPath cannot vouch for.
	needs string
}

// tools lists the backends in preference order. All three read the text
// from standard input when given "-" as their file argument.
var tools = []tool{
	{bin: "wtype", args: []string{"-"}, needs: "WAYLAND_DISPLAY"},
	{bin: "xdotool", args: []string{"type", "--clearmodifiers", "--file", "-"}, needs: "DISPLAY"},
	{bin: "ydotool", args: []string{"type", "--file", "-"}},
}

// Type types text into the window that has focus, using the first tool
// this session can run.
//
// The tool's own failure is returned as-is rather than cascaded to the
// next candidate: a half-typed password from a broken tool followed by a
// full retry from another would corrupt whatever field received it.
func Type(ctx context.Context, text string) error {
	for _, tl := range tools {
		if tl.needs != "" && !envSet(tl.needs) {
			continue
		}
		if _, err := exec.LookPath(tl.bin); err != nil {
			continue
		}
		cmd := exec.CommandContext(ctx, tl.bin, tl.args...) //nolint:gosec // fixed table.
		cmd.Stdin = strings.NewReader(text)
		return cmd.Run()
	}
	return ErrNoTool
}

// envSet reports whether the variable is present and non-empty.
func envSet(name string) bool {
	v := os.Getenv(name)
	return len(v) > 0
}
