package cli

import (
	"fmt"

	"github.com/71g3pf4c3/binpass/internal/theme"
	"github.com/71g3pf4c3/binpass/internal/tui"
	"github.com/spf13/cobra"
)

// newTUICmd builds `binpass tui`, the interactive terminal interface.
func newTUICmd(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tui",
		Short: "Interactive terminal interface for the password store",
		Long: `A persistent TUI session for browsing, searching and managing the
password store. Entries are only decrypted when opened, so navigating the
tree never triggers hardware-token touches.

The TUI uses an alternate screen buffer so that secrets do not leak into
terminal scrollback. An inactivity timer locks the session after 5 minutes
and clears decrypted secrets from memory.`,
		Args: cobra.NoArgs,
		RunE: func(_ /*cmd*/ *cobra.Command, _ []string) error {
			// The config file already rejects unknown themes; the only
			// unvalidated source left is this flag.
			if !theme.Valid(app.Cfg.Theme) {
				return fmt.Errorf("tui: unknown theme %q (available: %s)", app.Cfg.Theme, theme.String())
			}
			return runTUI(app)
		},
	}
	cmd.Flags().StringVar(&app.Cfg.Theme, "theme", app.Cfg.Theme,
		fmt.Sprintf("colour theme (%s)", theme.String()))
	// The error is unreachable — the flag was registered two lines above —
	// and cobra offers no way to express that without swallowing it.
	_ = cmd.RegisterFlagCompletionFunc("theme",
		func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
			return theme.Names(), cobra.ShellCompDirectiveNoFileComp
		})
	return cmd
}

// runTUI starts the TUI event loop.
func runTUI(app *App) error {
	s, err := app.requireStore()
	if err != nil {
		return err
	}
	code := tui.Run(tui.Options{Store: s, Cfg: app.Cfg})
	if code != 0 {
		return fmt.Errorf("tui exited with code %d", code)
	}
	return nil
}
