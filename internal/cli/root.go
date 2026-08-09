package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"

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
	app.Version = version

	root := newRootCmd(app, version, commit, buildDate)

	// Plugins are dispatched before cobra parses anything. A plugin's flags
	// are its own, and cobra would reject `binpass foo --bar` as an unknown
	// flag long before the plugin could be told about it. This is the same
	// order kubectl uses, and for the same reason.
	if handled, err := app.dispatchPlugin(context.Background(), root, os.Args[1:]); handled {
		if err == nil {
			return 0
		}
		var exit *exitError
		if errors.As(err, &exit) {
			return exit.code
		}
		fmt.Fprintln(app.Err, err)
		return 1
	}

	if err := root.Execute(); err != nil {
		// A plugin's own exit status passes through untouched, so that a
		// script wrapping `binpass foo` can tell what foo decided.
		var exit *exitError
		if errors.As(err, &exit) {
			return exit.code
		}
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

// exitError carries a specific process exit code up to Execute.
type exitError struct{ code int }

// Error describes the exit code.
func (e *exitError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

// exitCode extracts the exit status from a failed command, if it has one.
func exitCode(err error) (int, bool) {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), true
	}
	return 0, false
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
		// foo`, exactly as pass dispatches. A plugin gets the name first,
		// so that `binpass foo` reaches binpass-foo when one exists; an
		// entry named foo is still reachable as `binpass show foo`.
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return app.runList(cmd.Context(), "")
			}
			return app.runShow(cmd.Context(), showOpts{name: args[0]})
		},
	}
	root.PersistentFlags().StringVar(&app.Cfg.Dir, "store", app.Cfg.Dir, "password store directory")
	root.PersistentFlags().StringVar(&app.Cfg.Identity, "identity", app.Cfg.Identity, "age identity file")

	root.ValidArgsFunction = app.completeRootArg

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
		newTombCmd(app),
		newDoctorCmd(app),
		newBinaryCmd(app),
		newImportCmd(app),
		newExportCmd(app),
		newAuditCmd(app),
		newCompletionCmd(app),
		newPluginCmd(app),
		newVersionCmd(app, version, commit, buildDate),
	)
	registerCompletions(app, root)
	return root
}

// registerCompletions wires store-aware argument completion onto the commands
// that take an entry name, so that tab-completion walks the password tree.
func registerCompletions(app *App, root *cobra.Command) {
	// Commands taking exactly one existing entry.
	entryCommands := []string{"show", "edit", "otp", "generate"}
	// Commands taking an entry or a subfolder, possibly twice.
	treeCommands := []string{"ls", "list", "rm", "remove", "delete", "mv", "rename", "cp", "copy", "insert", "import", "export", "audit", "binary"}

	for _, c := range root.Commands() {
		name := c.Name()
		switch {
		case contains(entryCommands, name):
			c.ValidArgsFunction = app.completeEntries
		case contains(treeCommands, name):
			c.ValidArgsFunction = app.completeEntriesAndDirs
		}
	}
}

// contains reports whether needle is in haystack.
func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
