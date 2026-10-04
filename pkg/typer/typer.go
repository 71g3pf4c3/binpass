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
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// ErrNoTool reports that no typing tool is available in this session.
var ErrNoTool = errors.New("typer: no typing tool found; install wtype, ydotool or xdotool")

// ToolAuto names autodetection: the first tool this session can run.
const ToolAuto = "auto"

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

// ToolNames returns the tool names TypeWithTool accepts, autodetection
// first. It is the single list the flag help, the completion and the
// unknown-name error are built from, so they cannot drift apart.
func ToolNames() []string {
	names := make([]string, 0, len(tools)+1)
	names = append(names, ToolAuto)
	for _, tl := range tools {
		names = append(names, tl.bin)
	}
	return names
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
		return tl.run(ctx, text)
	}
	return ErrNoTool
}

// TypeWithTool types text with the backend named on the command line
// instead of the detected one. The name is one of ToolNames; the empty
// string and ToolAuto fall back to Type's detection.
//
// The session variables that gate autodetection are deliberately not
// enforced here: an explicit choice overrides what the environment claims
// about the session, because environments do lie — a launcher started
// before the compositor can miss WAYLAND_DISPLAY on a Wayland desktop
// just as an SSH login can inherit a stale DISPLAY. The tool's own
// failure is the honest answer. Presence on PATH is still checked, so a
// missing binary is reported in binpass's words rather than the exec
// package's.
func TypeWithTool(ctx context.Context, name, text string) error {
	if name == "" || name == ToolAuto {
		return Type(ctx, text)
	}
	tl, ok := toolByName(name)
	if !ok {
		return unknownToolError(name)
	}
	if _, err := exec.LookPath(tl.bin); err != nil {
		return fmt.Errorf("typer: %s is not installed", tl.bin)
	}
	return tl.run(ctx, text)
}

// ParseTool validates a typing tool name, returning it unchanged. The
// empty string and ToolAuto pass: they mean autodetection.
//
// It exists so a command can reject a typo before the store is decrypted
// and the picker is drawn, rather than after the secret has been read.
func ParseTool(name string) (string, error) {
	if name == "" || name == ToolAuto {
		return name, nil
	}
	if _, ok := toolByName(name); !ok {
		return "", unknownToolError(name)
	}
	return name, nil
}

// toolByName finds a backend by the name used on the command line.
func toolByName(name string) (tool, bool) {
	for _, tl := range tools {
		if tl.bin == name {
			return tl, true
		}
	}
	return tool{}, false
}

// unknownToolError reports an unrecognized name alongside the valid ones.
func unknownToolError(name string) error {
	return fmt.Errorf("typer: unknown tool %q; valid: %s", name, strings.Join(ToolNames(), ", "))
}

// run feeds text to the tool on standard input. The fixed argument table
// ends in a stdin marker, so the secret never becomes an argument.
func (t tool) run(ctx context.Context, text string) error {
	cmd := exec.CommandContext(ctx, t.bin, t.args...) //nolint:gosec // fixed table.
	cmd.Stdin = strings.NewReader(text)
	return cmd.Run()
}

// envSet reports whether the variable is present and non-empty.
func envSet(name string) bool {
	v := os.Getenv(name)
	return len(v) > 0
}
