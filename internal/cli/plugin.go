package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

// pluginLockPath is where the approvals the user gave are recorded.
//
// It sits in the data directory beside the managed plugins and deliberately
// outside the store: a lock file that travelled with the store could be
// rewritten by whatever planted the plugin it is supposed to vouch for.
func (a *App) pluginLockPath() string {
	return filepath.Join(config.DataDir(), plugin.LockName)
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
	cmd.AddCommand(newPluginTrustCmd(app))
	return cmd
}

// newPluginTrustCmd builds `binpass plugin trust`.
func newPluginTrustCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "trust <name>",
		Short: "Approve a plugin at its current contents and capabilities",
		Long: "Records consent for a plugin in plugins.lock. A plugin carrying a\n" +
			"manifest does not run until it has been approved here, and approval is\n" +
			"bound to the executable's digest and to the capabilities the manifest\n" +
			"asked for: an update that rewrites the binary, or a manifest edited to\n" +
			"request more, has to be approved again.\n\n" +
			"Read the plugin before approving it. That is the actual boundary.",
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return app.runPluginTrust(args[0])
		},
	}
}

// runPluginTrust records consent for a plugin at its current digest.
func (a *App) runPluginTrust(name string) error {
	p, err := a.pluginSource().Find(name)
	if err != nil {
		return fmt.Errorf("binpass plugin trust: %s: %w", name, err)
	}
	if !p.Managed {
		return fmt.Errorf("binpass plugin trust: %s carries no manifest, so there is nothing to approve", name)
	}
	if p.Path == "" {
		return fmt.Errorf("binpass plugin trust: %s has nothing to execute", name)
	}
	digest, err := plugin.DigestFile(p.Path)
	if err != nil {
		return err
	}
	lock, err := plugin.LoadLock(a.pluginLockPath())
	if err != nil {
		return err
	}

	fmt.Fprintf(a.Out, "%s %s\n", p.Manifest.Name, p.Manifest.Version)
	if p.Manifest.Description != "" {
		fmt.Fprintf(a.Out, "  %s\n", p.Manifest.Description)
	}
	fmt.Fprintf(a.Out, "  path:   %s\n", p.Path)
	fmt.Fprintf(a.Out, "  digest: %s\n", digest)
	fmt.Fprint(a.Out, p.Manifest.Summary())
	// Where the plugin came from decides how much the approval is worth:
	// anything able to write to the store can replace a plugin that lives
	// inside it, and the next approval prompt is the only warning.
	if withinStore(a.Cfg.Dir, p.Dir) {
		fmt.Fprintln(a.Err, "Warning: this plugin lives inside the password store, so it arrives with every sync.")
	}

	lock.Grant(p.Manifest, digest)
	if err := lock.Save(a.pluginLockPath()); err != nil {
		return err
	}
	fmt.Fprintf(a.Out, "Approved %s.\n", p.Manifest.Name)
	return nil
}

// withinStore reports whether dir lies inside the password store.
func withinStore(storeDir, dir string) bool {
	if storeDir == "" || dir == "" {
		return false
	}
	rel, err := filepath.Rel(storeDir, dir)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// checkPluginTrust refuses a manifest-carrying plugin the user has not
// approved at its current digest and capabilities.
//
// A plugin directory inside the store travels with every sync, so anyone able
// to write to the shared store could otherwise have their binary run with the
// victim's full authority the first time a command word matched its name —
// including an everyday typo, since dispatch happens before cobra can say
// "unknown command". Consent is checked here rather than at install time
// because there is no install step: a directory simply appears.
func (a *App) checkPluginTrust(p *plugin.Plugin) error {
	// Only a manifest records what could be approved. An unmanaged
	// executable on PATH is something the user put there themselves and
	// could equally have run directly.
	if !p.Managed || p.Path == "" {
		return nil
	}
	digest, err := plugin.DigestFile(p.Path)
	if err != nil {
		return err
	}
	lock, err := plugin.LoadLock(a.pluginLockPath())
	if err != nil {
		return err
	}
	state := lock.Check(p.Manifest, digest)
	if state == plugin.GrantValid {
		return nil
	}

	name := p.Manifest.Name
	fmt.Fprintf(a.Err, "binpass: plugin %q is %s.\n", name, state)
	fmt.Fprintf(a.Err, "  path:   %s\n", p.Path)
	fmt.Fprintf(a.Err, "  digest: %s\n", digest)
	fmt.Fprint(a.Err, p.Manifest.Summary())
	if withinStore(a.Cfg.Dir, p.Dir) {
		fmt.Fprintln(a.Err, "  source:  inside the password store, so it arrived with a sync")
	}
	return fmt.Errorf("binpass: refusing to run an unapproved plugin; review it and run %q",
		"binpass plugin trust "+name)
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
	if err := a.checkPluginTrust(res.Plugin); err != nil {
		return true, err
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
