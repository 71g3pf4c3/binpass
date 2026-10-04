package cli

import (
	"context"
	"strings"
	"time"

	"github.com/71g3pf4c3/binpass/pkg/typer"
	"github.com/spf13/cobra"
)

// newTypeCmd builds `binpass type`, which sends a secret as keystrokes to
// the focused window, for the forms that refuse a paste.
func newTypeCmd(app *App) *cobra.Command {
	var field string
	var delay time.Duration
	var tool string
	cmd := &cobra.Command{
		Use:   "type [--field=name] [--tool=name] pass-name",
		Short: "Type a secret into the focused window",
		Long: "Decrypts an entry and types the chosen field as keystrokes, so the secret\n" +
			"never touches the clipboard. The text is fed to the typing tool on\n" +
			"standard input, never as an argument, so it does not show in ps(1).\n\n" +
			"The typing tool is picked per session: wtype on Wayland, xdotool on X11,\n" +
			"ydotool on either. --tool forces a specific one regardless of what the\n" +
			"session claims to be, as do the BINPASS_TYPER_TOOL variable and the\n" +
			"typer.tool config setting; --delay waits before the first keystroke,\n" +
			"giving a hotkey-driven invocation time to land focus on the target\n" +
			"window.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Resolved and validated before the store is touched, so a
			// typo in the tool name fails fast.
			name, err := app.resolveTyperTool(cmd.Flags().Changed("tool"), tool)
			if err != nil {
				return err
			}
			return app.runType(cmd.Context(), args[0], field, delay, name)
		},
	}
	cmd.Flags().StringVar(&field, "field", "password", "what to type: password, all, otp, or a field name")
	_ = cmd.RegisterFlagCompletionFunc("field", app.completeFieldNames)
	cmd.Flags().StringVar(&tool, "tool", "auto", "typing tool: auto|wtype|xdotool|ydotool")
	_ = cmd.RegisterFlagCompletionFunc("tool", completeTyperTools)
	cmd.Flags().DurationVar(&delay, "delay", 0, "wait before typing, e.g. 300ms")
	return cmd
}

// resolveTyperTool decides which typing backend a command uses: an
// explicitly passed --tool, then the typer.tool setting (which the
// BINPASS_TYPER_TOOL variable feeds), then session autodetection. An
// explicit --tool=auto still counts as a choice, so the flag can cancel
// the setting.
//
// The value is validated here so a typo fails before the store is
// decrypted and the picker is drawn, not after.
func (a *App) resolveTyperTool(changed bool, flagValue string) (string, error) {
	tool := "auto"
	if changed {
		tool = flagValue
	} else if a.Cfg.TyperTool != "" {
		tool = a.Cfg.TyperTool
	}
	return typer.ParseTool(tool)
}

// completeTyperTools completes the --tool flag.
func completeTyperTools(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	var out []string
	for _, n := range typer.ToolNames() {
		if strings.HasPrefix(n, toComplete) {
			out = append(out, n)
		}
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}

// runType resolves the field and types it. The tool is already resolved
// and validated by the command; "" means session autodetection.
func (a *App) runType(ctx context.Context, name, field string, delay time.Duration, tool string) error {
	s, err := a.requireStore()
	if err != nil {
		return err
	}
	sec, err := s.Get(name)
	if err != nil {
		return err
	}
	value, err := a.fieldValue(s, name, sec, field)
	if err != nil {
		return err
	}
	if delay > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
	return typer.TypeWithTool(ctx, tool, value)
}
