package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
)

// menuOpts holds the parsed flags of `binpass menu`.
type menuOpts struct {
	// launcher names the picker to use, or "auto" to detect one.
	launcher string
	// field selects what to emit: password, a named field, or the whole entry.
	field string
	// typeIt types the secret into the focused window instead of copying it.
	typeIt bool
	// print writes the secret to stdout instead of the clipboard.
	print bool
	// prompt is the label shown by the picker.
	prompt string
	// args are extra arguments passed straight to the picker.
	args []string
}

// newMenuCmd builds `binpass menu`, the built-in equivalent of passmenu and
// rofi-pass: it lists entries in a picker and acts on the chosen one.
func newMenuCmd(app *App) *cobra.Command {
	opts := menuOpts{launcher: "auto", field: "password", prompt: "pass"}
	cmd := &cobra.Command{
		Use:   "menu [-- launcher-args...]",
		Short: "Pick a password with rofi, fzf, dmenu or wofi",
		Long: "Lists the store in an interactive picker and copies, prints or types the\n" +
			"chosen secret. Replaces passmenu, rofi-pass and fzf-pass without a wrapper\n" +
			"script: the store is never decrypted until an entry is actually chosen.",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.args = args
			return app.runMenu(cmd.Context(), opts)
		},
	}
	cmd.Flags().StringVar(&opts.launcher, "launcher", "auto", "picker: auto|rofi|fzf|dmenu|wofi|wmenu")
	cmd.Flags().StringVar(&opts.field, "field", "password", "what to emit: password, all, or a field name")
	cmd.Flags().BoolVar(&opts.typeIt, "type", false, "type the secret into the focused window")
	cmd.Flags().BoolVar(&opts.print, "print", false, "write the secret to stdout")
	cmd.Flags().StringVar(&opts.prompt, "prompt", "pass", "picker prompt")
	return cmd
}

// runMenu lists the store, asks the picker for a choice, and acts on it.
func (a *App) runMenu(ctx context.Context, opts menuOpts) error {
	s, err := a.requireStore()
	if err != nil {
		return err
	}
	names, err := s.List("")
	if err != nil {
		return err
	}
	if len(names) == 0 {
		return errors.New("binpass: the password store is empty")
	}

	picker, err := detectPicker(opts.launcher)
	if err != nil {
		return err
	}
	choice, err := picker.pick(ctx, names, opts)
	if err != nil {
		return err
	}
	if choice == "" {
		// The user dismissed the picker, which is not a failure.
		return nil
	}

	sec, err := s.Get(choice)
	if err != nil {
		return err
	}

	var value string
	switch opts.field {
	case "password":
		value = sec.Password()
	case "all":
		value = sec.String()
	default:
		v, ok := sec.Field(opts.field)
		if !ok {
			return fmt.Errorf("binpass: %s has no field %q", choice, opts.field)
		}
		value = v
	}

	switch {
	case opts.print:
		fmt.Fprintln(a.Out, value)
		return nil
	case opts.typeIt:
		return typeText(ctx, value)
	default:
		return a.copyToClipboard(ctx, value, choice)
	}
}

// picker is an interactive chooser backed by an external program.
type picker struct {
	// name identifies the picker.
	name string
	// bin is the executable on PATH.
	bin string
	// args builds the command line for a given prompt.
	args func(prompt string) []string
	// needsTTY marks a picker that draws on the terminal rather than in a
	// window, and so must inherit stderr.
	needsTTY bool
}

// pickers lists the supported launchers in detection order: graphical ones
// first, since a terminal picker cannot be used from a keybinding.
func pickers() []picker {
	return []picker{
		{
			name: "rofi",
			bin:  "rofi",
			args: func(p string) []string { return []string{"-dmenu", "-i", "-p", p} },
		},
		{
			name: "wofi",
			bin:  "wofi",
			args: func(p string) []string { return []string{"--dmenu", "-i", "-p", p} },
		},
		{
			name: "dmenu",
			bin:  "dmenu",
			args: func(p string) []string { return []string{"-i", "-p", p} },
		},
		{
			name: "wmenu",
			bin:  "wmenu",
			args: func(p string) []string { return []string{"-i", "-p", p} },
		},
		{
			name:     "fzf",
			bin:      "fzf",
			args:     func(p string) []string { return []string{"--prompt", p + "> ", "--height", "40%", "--reverse"} },
			needsTTY: true,
		},
	}
}

// detectPicker returns the requested picker, or the first available one.
func detectPicker(name string) (picker, error) {
	all := pickers()
	if name != "" && name != "auto" {
		for _, p := range all {
			if p.name == name {
				if _, err := exec.LookPath(p.bin); err != nil {
					return picker{}, fmt.Errorf("binpass: %s is not installed", p.bin)
				}
				return p, nil
			}
		}
		return picker{}, fmt.Errorf("binpass: unknown launcher %q", name)
	}
	// A graphical picker is only usable inside a graphical session.
	graphical := os.Getenv("WAYLAND_DISPLAY") != "" || os.Getenv("DISPLAY") != ""
	for _, p := range all {
		if p.needsTTY == graphical {
			continue
		}
		if _, err := exec.LookPath(p.bin); err == nil {
			return p, nil
		}
	}
	for _, p := range all {
		if _, err := exec.LookPath(p.bin); err == nil {
			return p, nil
		}
	}
	return picker{}, errors.New("binpass: no picker found; install rofi, fzf, dmenu or wofi")
}

// pick runs the picker over names and returns the chosen entry, or an empty
// string when the user dismissed it.
func (p picker) pick(ctx context.Context, names []string, opts menuOpts) (string, error) {
	args := append(p.args(opts.prompt), opts.args...)
	cmd := exec.CommandContext(ctx, p.bin, args...) //nolint:gosec // the binary comes from a fixed table.
	cmd.Stdin = strings.NewReader(strings.Join(names, "\n") + "\n")
	if p.needsTTY {
		cmd.Stderr = os.Stderr
	}

	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			// Every supported picker exits non-zero when cancelled.
			return "", nil
		}
		return "", fmt.Errorf("binpass: %s: %w", p.bin, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// typeText types a secret into the focused window using the session's
// automation tool, so that a password reaches a form that refuses pasting.
func typeText(ctx context.Context, text string) error {
	type typer struct {
		// bin is the executable to run.
		bin string
		// args builds its command line.
		args []string
		// stdin reports whether the text is fed on standard input.
		stdin bool
	}
	candidates := []typer{
		{bin: "wtype", args: []string{"-"}, stdin: true},
		{bin: "ydotool", args: []string{"type", "--file", "-"}, stdin: true},
		{bin: "xdotool", args: []string{"type", "--clearmodifiers", "--file", "-"}, stdin: true},
	}
	for _, c := range candidates {
		if _, err := exec.LookPath(c.bin); err != nil {
			continue
		}
		cmd := exec.CommandContext(ctx, c.bin, c.args...) //nolint:gosec // fixed table.
		if c.stdin {
			cmd.Stdin = strings.NewReader(text)
		}
		return cmd.Run()
	}
	return errors.New("binpass: no typing tool found; install wtype, ydotool or xdotool")
}
