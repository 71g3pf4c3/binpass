package cli

import (
	"fmt"
	"os"

	"github.com/71g3pf4c3/binpass/internal/config"
	"github.com/spf13/cobra"
)

// Execute builds the command tree and runs it, returning the process exit
// code. pass exits 1 on any error, and so do we.
func Execute(version, commit, buildDate string) int {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	app := NewApp(cfg)

	root := newRootCmd(app, version, commit, buildDate)
	if err := root.Execute(); err != nil {
		// Cobra has already printed usage errors; ours are printed here.
		if !isUsageError(err) {
			fmt.Fprintln(app.Err, err)
		}
		return 1
	}
	return 0
}

// usageError marks an error whose message cobra has already shown.
type usageError struct{ error }

// isUsageError reports whether err was already reported by cobra.
func isUsageError(err error) bool {
	_, ok := err.(usageError) //nolint:errorlint // the wrapper is never wrapped further.
	return ok
}

// newRootCmd assembles the command tree.
func newRootCmd(app *App, version, commit, buildDate string) *cobra.Command {
	root := &cobra.Command{
		Use:   "binpass",
		Short: "A pass(1)-compatible password manager",
		// pass prints its own diagnostics; cobra's extra noise would break
		// output compatibility.
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ArbitraryArgs,
		// Bare `binpass` is `binpass ls`, and `binpass foo` is `binpass show
		// foo`, exactly as pass dispatches.
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return app.runList(cmd.Context(), "")
			}
			return app.runShow(cmd.Context(), showOpts{name: args[0]})
		},
	}
	root.PersistentFlags().StringVar(&app.Cfg.Dir, "store", app.Cfg.Dir, "password store directory")
	root.PersistentFlags().StringVar(&app.Cfg.Identity, "identity", app.Cfg.Identity, "age identity file")

	root.AddCommand(
		newInitCmd(app),
		newListCmd(app),
		newShowCmd(app),
		newFindCmd(app),
		newGrepCmd(app),
		newInsertCmd(app),
		newEditCmd(app),
		newGenerateCmd(app),
		newRemoveCmd(app),
		newMoveCmd(app),
		newCopyCmd(app),
		newGitCmd(app),
		newMenuCmd(app),
		newOTPCmd(app),
		newVersionCmd(app, version, commit, buildDate),
	)
	return root
}
