package cli

import (
	"context"
	"time"

	"github.com/71g3pf4c3/binpass/pkg/typer"
	"github.com/spf13/cobra"
)

// newTypeCmd builds `binpass type`, which sends a secret as keystrokes to
// the focused window, for the forms that refuse a paste.
func newTypeCmd(app *App) *cobra.Command {
	var field string
	var delay time.Duration
	cmd := &cobra.Command{
		Use:   "type [--field=name] pass-name",
		Short: "Type a secret into the focused window",
		Long: "Decrypts an entry and types the chosen field as keystrokes, so the secret\n" +
			"never touches the clipboard. The text is fed to the typing tool on\n" +
			"standard input, never as an argument, so it does not show in ps(1).\n\n" +
			"The typing tool is picked per session: wtype on Wayland, xdotool on X11,\n" +
			"ydotool on either. --delay waits before the first keystroke, giving a\n" +
			"hotkey-driven invocation time to land focus on the target window.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return app.runType(cmd.Context(), args[0], field, delay)
		},
	}
	cmd.Flags().StringVar(&field, "field", "password", "what to type: password, all, otp, or a field name")
	_ = cmd.RegisterFlagCompletionFunc("field", app.completeFieldNames)
	cmd.Flags().DurationVar(&delay, "delay", 0, "wait before typing, e.g. 300ms")
	return cmd
}

// runType resolves the field and types it.
func (a *App) runType(ctx context.Context, name, field string, delay time.Duration) error {
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
	return typer.Type(ctx, value)
}
