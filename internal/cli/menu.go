package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/71g3pf4c3/binpass/internal/config"
	"github.com/71g3pf4c3/binpass/pkg/otp"
	"github.com/71g3pf4c3/binpass/pkg/secret"
	"github.com/71g3pf4c3/binpass/pkg/store"
	"github.com/71g3pf4c3/binpass/pkg/typer"
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
	// sort orders the list before it reaches the picker: by name, by how
	// often an entry was chosen, or by how recently.
	sort string
	// reverse flips the order the sort produced.
	reverse bool
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
			"script: the store is never decrypted until an entry is actually chosen.\n\n" +
			"--sort=frequent and --sort=recent order the list by how the entry has been\n" +
			"used in this menu before, so the daily ones float to the top; --field=otp\n" +
			"generates the entry's one-time password instead of its first line.",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.args = args
			return app.runMenu(cmd.Context(), opts)
		},
	}
	cmd.Flags().StringVar(&opts.launcher, "launcher", "auto", "picker: auto|rofi|fzf|dmenu|wofi|wmenu")
	cmd.Flags().StringVar(&opts.field, "field", "password", "what to emit: password, all, or a field name")
	_ = cmd.RegisterFlagCompletionFunc("launcher", completeLauncherNames)
	_ = cmd.RegisterFlagCompletionFunc("field", app.completeFieldNames)
	cmd.Flags().BoolVar(&opts.typeIt, "type", false, "type the secret into the focused window")
	cmd.Flags().BoolVar(&opts.print, "print", false, "write the secret to stdout")
	cmd.Flags().StringVar(&opts.prompt, "prompt", "pass", "picker prompt")
	cmd.Flags().StringVar(&opts.sort, "sort", "name", "list order: name, frequent, recent")
	_ = cmd.RegisterFlagCompletionFunc("sort", completeSortModes)
	cmd.Flags().BoolVar(&opts.reverse, "reverse", false, "flip the sort order")
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
	// The usage history decides frequent and recent ordering — and a
	// missing or corrupt file simply means nobody has used the menu yet.
	usage := loadMenuUsage()
	names = sortEntries(names, opts.sort, opts.reverse, usage)

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

	// A choice is a use, even if the clipboard later fails: the user went
	// looking for this entry, and that is what frequent and recent rank.
	usage.mark(choice)
	saveMenuUsage(usage)

	sec, err := s.Get(choice)
	if err != nil {
		return err
	}

	value, err := a.fieldValue(s, choice, sec, opts.field)
	if err != nil {
		return err
	}

	switch {
	case opts.print:
		fmt.Fprintln(a.Out, value)
		return nil
	case opts.typeIt:
		// The picker's window has only just closed; give the session a
		// beat to hand focus back before the first keystroke lands, or
		// the head of the secret is typed into a dying window.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pickerSettle):
		}
		return typer.Type(ctx, value)
	default:
		return a.copyToClipboard(ctx, value, choice)
	}
}

// pickerSettle is the pause between the picker closing and the first
// keystroke of --type.
const pickerSettle = 150 * time.Millisecond

// fieldValue resolves what a menu or type invocation emits for an entry:
// the password, the whole secret, the computed otp, or a named field.
func (a *App) fieldValue(s *store.Store, choice string, sec *secret.Secret, field string) (string, error) {
	switch field {
	case "password":
		return sec.Password(), nil
	case "all":
		return sec.String(), nil
	case "otp":
		// The one field that is not stored but computed. Sharing the code
		// path with `otp` keeps HOTP counter advancement identical.
		return a.otpCode(s, choice, sec)
	default:
		v, ok := sec.Field(field)
		if !ok {
			return "", fmt.Errorf("binpass: %s has no field %q", choice, field)
		}
		return v, nil
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

// menuUsage records how often and how recently each entry was chosen in the
// menu, which is all the frequent and recent sorts have to go on. It lives in
// the state directory, never in the store: usage counts are binpass's own
// bookkeeping, and the store must stay exactly what pass understands.
type menuUsage map[string]*menuUse

// menuUse is the usage record of one entry.
type menuUse struct {
	// Count is how many times the entry was chosen in the menu.
	Count int `json:"count"`
	// Last is when it was last chosen, RFC 3339.
	Last time.Time `json:"last"`
}

// mark records a choice of name.
func (m menuUsage) mark(name string) {
	u := m[name]
	if u == nil {
		u = &menuUse{}
		m[name] = u
	}
	u.Count++
	u.Last = time.Now()
}

// menuUsagePath is the file the usage lives in.
func menuUsagePath() string {
	return filepath.Join(config.StateDir(), "menu-usage.json")
}

// loadMenuUsage reads the usage file, treating anything unreadable as no
// history: sorting must never fail the picker over its own bookkeeping.
func loadMenuUsage() menuUsage {
	usage := menuUsage{}
	data, err := os.ReadFile(menuUsagePath()) //nolint:gosec // a fixed path in the state directory.
	if err != nil {
		return usage
	}
	_ = json.Unmarshal(data, &usage)
	return usage
}

// saveMenuUsage writes the usage file atomically: a half-written history is
// worse than a lost one, because it silently reorders someone's menu.
func saveMenuUsage(usage menuUsage) {
	path := menuUsagePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	data, err := json.Marshal(usage)
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".menu-usage-*") // 0600 by default.
	if err != nil {
		return
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return
	}
	_ = os.Rename(name, path)
}

// sortEntries orders names for the picker. name is the store's own order;
// frequent ranks by how often an entry was chosen, recent by how lately —
// an entry never chosen ranks by name at the end. reverse flips whatever
// the mode produced.
func sortEntries(names []string, mode string, reverse bool, usage menuUsage) []string {
	out := append([]string{}, names...)
	switch mode {
	case "frequent":
		sort.SliceStable(out, func(i, j int) bool {
			a, b := usage[out[i]], usage[out[j]]
			ai, bi := 0, 0
			if a != nil {
				ai = a.Count
			}
			if b != nil {
				bi = b.Count
			}
			if ai != bi {
				return ai > bi
			}
			return out[i] < out[j]
		})
	case "recent":
		sort.SliceStable(out, func(i, j int) bool {
			a, b := usage[out[i]], usage[out[j]]
			if a != nil && b != nil && !a.Last.Equal(b.Last) {
				return a.Last.After(b.Last)
			}
			if (a == nil) != (b == nil) {
				return b == nil // never-used goes last
			}
			return out[i] < out[j]
		})
	case "name", "":
		sort.Strings(out)
	default:
		sort.Strings(out)
	}
	if reverse {
		for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
			out[i], out[j] = out[j], out[i]
		}
	}
	return out
}

// completeSortModes completes the --sort flag.
func completeSortModes(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	modes := []string{"name", "frequent", "recent"}
	var out []string
	for _, m := range modes {
		if strings.HasPrefix(m, toComplete) {
			out = append(out, m)
		}
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}

// otpCode produces the current one-time password for an entry, advancing a
// HOTP counter exactly as the otp command does — the menu and the command
// must not disagree about which code is current.
func (a *App) otpCode(s *store.Store, name string, sec *secret.Secret) (string, error) {
	uri, ok := sec.OTP()
	if !ok {
		return "", fmt.Errorf("Error: %s has no otpauth:// URI.", name) //nolint:revive,staticcheck // pass-otp's diagnostic style.
	}
	cfg, err := otp.Parse(uri)
	if err != nil {
		return "", err
	}
	code, err := cfg.Code(time.Now())
	if err != nil {
		return "", err
	}
	if cfg.Kind == otp.HOTP {
		if err := a.advanceHOTP(s, name, sec, uri, cfg); err != nil {
			return "", err
		}
	}
	return code, nil
}
