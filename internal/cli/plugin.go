package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/71g3pf4c3/binpass/internal/config"
	"github.com/71g3pf4c3/binpass/pkg/plugin"
	"github.com/spf13/cobra"
)

// pluginSource returns where this invocation looks for plugins.
func (a *App) pluginSource() plugin.Source {
	return plugin.DefaultSource(config.DataDir(), a.Cfg.Dir)
}

// newPluginCmd builds `binpass plugin`.
func newPluginCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "plugin",
		Short: "Manage binpass plugins",
		Long: "Plugins are executables named binpass-* on your PATH.\n" +
			"Any file named binpass-foo provides the command `binpass foo`.",
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			return c.Help()
		},
	}
	cmd.AddCommand(newPluginListCmd(app))
	return cmd
}

// newPluginListCmd builds `binpass plugin list`.
func newPluginListCmd(app *App) *cobra.Command {
	var nameOnly bool
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List the plugins binpass can see",
		Args:    cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			return app.runPluginList(c, nameOnly)
		},
	}
	cmd.Flags().BoolVar(&nameOnly, "name-only", false, "print only plugin names")
	return cmd
}

// runPluginList reports every plugin-shaped file found, including the ones
// that will not run.
//
// Unusable files are listed rather than hidden: a plugin that fails to appear
// because its executable bit is unset, or because another copy earlier on
// PATH wins, is otherwise a genuinely baffling thing to debug.
func (a *App) runPluginList(cmd *cobra.Command, nameOnly bool) error {
	found := a.pluginSource().Candidates(builtinNames(cmd.Root()))
	if len(found) == 0 {
		fmt.Fprintln(a.Err, "No plugins found.")
		fmt.Fprintln(a.Err, "Put an executable named binpass-<name> on your PATH to add one.")
		return nil
	}

	if nameOnly {
		for _, c := range found {
			if c.Usable() {
				fmt.Fprintln(a.Out, c.Name)
			}
		}
		return nil
	}

	w := tabwriter.NewWriter(a.Out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "COMMAND\tPATH\tSTATUS")
	var problems int
	for _, c := range found {
		status := "ok"
		switch {
		case c.ShadowsBuiltin != "":
			status = "shadowed by the builtin command " + c.ShadowsBuiltin
			problems++
		case c.ShadowedBy != "":
			status = "shadowed by " + c.ShadowedBy
			problems++
		case !c.Executable:
			status = "not executable"
			problems++
		}
		fmt.Fprintf(w, "binpass %s\t%s\t%s\n", c.Name, c.Path, status)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if problems > 0 {
		fmt.Fprintf(a.Err, "\n%d plugin(s) will not run; see STATUS above.\n", problems)
	}
	return nil
}

// builtinNames returns the command names a plugin cannot override, including
// aliases: `binpass-list` is as unreachable as `binpass-ls`.
func builtinNames(root *cobra.Command) []string {
	var out []string
	for _, c := range root.Commands() {
		out = append(out, c.Name())
		out = append(out, c.Aliases...)
	}
	sort.Strings(out)
	return out
}

// isBuiltin reports whether name is a command binpass provides itself.
func isBuiltin(root *cobra.Command, name string) bool {
	for _, c := range root.Commands() {
		if c.Name() == name {
			return true
		}
		for _, a := range c.Aliases {
			if a == name {
				return true
			}
		}
	}
	// Cobra generates these, and they must keep working even when a
	// same-named executable is on PATH.
	return name == "help" || name == "__complete" || name == "__completeNoDesc"
}

// dispatchPlugin runs the plugin providing a command, if one does.
//
// It runs before cobra parses the command line, because a plugin's flags
// belong to the plugin: cobra would reject `binpass foo --bar` as an unknown
// flag before the plugin ever saw it.
//
// Built-in commands always win. A plugin that could shadow `show` or `insert`
// would be able to silently replace the commands that handle secrets, which
// is not a trade worth making for extensibility. Such a plugin is reported by
// `binpass plugin list` rather than being quietly ignored.
func (a *App) dispatchPlugin(ctx context.Context, root *cobra.Command, args []string) (bool, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return false, nil
	}
	if isBuiltin(root, args[0]) {
		return false, nil
	}
	res, ok := a.pluginSource().Resolve(args)
	if !ok {
		return false, nil
	}
	self, err := os.Executable()
	if err != nil {
		return true, err
	}
	runner := &plugin.Runner{
		Bin:      self,
		StoreDir: a.Cfg.Dir,
		Version:  a.Version,
		Stdin:    os.Stdin,
		Stdout:   a.Out,
		Stderr:   a.Err,
	}
	err = runner.Run(ctx, res.Plugin, res.Args)
	return true, pluginExitError(res.Command, err)
}

// pluginExitError preserves a plugin's exit status.
//
// A plugin that exits 3 must make binpass exit 3, or a script wrapping it
// cannot tell success from failure. Only the failure to start it at all is
// reported as binpass's own error.
func pluginExitError(command string, err error) error {
	if err == nil {
		return nil
	}
	var exit *exitError
	if errors.As(err, &exit) {
		return err
	}
	if code, ok := exitCode(err); ok {
		return &exitError{code: code}
	}
	return fmt.Errorf("binpass %s: %w", command, err)
}
