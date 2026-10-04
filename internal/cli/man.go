package cli

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/71g3pf4c3/binpass/internal/theme"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

// newManCmd builds the hidden `binpass man` command.
//
// It is the packaging surface for the manual: the nix package, the pass shim
// and the goreleaser build all produce their man pages by running the binary
// they are about to ship, exactly as they already do for shell completions. A
// page generated from the live command tree cannot drift from the flags the
// binary actually accepts; a committed page can, and a password manager that
// documents a flag it dropped is worse than one with no manual at all.
//
// The command is hidden rather than omitted: `binpass help` must keep
// matching pass's command surface for the golden tests, and a documentation
// generator is not a pass command.
func newManCmd(app *App, version, buildDate string) *cobra.Command {
	return &cobra.Command{
		Use:    "man [dir]",
		Short:  "Write manual pages into a directory",
		Hidden: true,
		Args:   cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := "."
			if len(args) == 1 {
				dir = args[0]
			}
			return writeManPages(cmd.Root(), dir, version, buildDate)
		},
	}
}

// writeManPages renders a page for root and every visible subcommand into
// dir, named after the command path (`binpass init` becomes binpass-init.1).
// Because the root command is named after the binary it was invoked as, the
// same invocation installed as `pass` yields pass.1 — the manual follows the
// name, like the completions do.
func writeManPages(root *cobra.Command, dir, version, buildDate string) error {
	header := &doc.GenManHeader{
		Section: "1",
		Source:  "binpass " + version,
		Manual:  "User Commands",
	}
	// A page stamped with the build date can be traced to the release it
	// shipped in. Plain `go build` carries no date ("unknown"), and then
	// cobra falls back to SOURCE_DATE_EPOCH — which is what keeps nix
	// builds bit-reproducible — or to now, which is right for a local
	// checkout. The date is deliberately not faked when it is not known.
	if t, err := time.Parse(time.RFC3339, buildDate); err == nil {
		header.Date = &t
	}
	// The directory is created 0755, like every /usr/share/man out there:
	// these are public pages, and a directory nobody can traverse would
	// defeat the 0644 files inside it.
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // G301: documentation is world-readable by convention.
		return err
	}
	scrubEnvDerivedDefaults(root)
	if err := doc.GenManTree(root, header, dir); err != nil {
		return err
	}
	return chmodManPages(root, dir)
}

// envDerivedDefaults lists the flags whose default config.Load has already
// resolved from the machine the generator runs on: the store and identity
// paths expand the home directory, and the theme can be overridden from the
// environment. A man page is built once and shipped to everyone, so it must
// print the documented default, not wherever the build machine keeps its
// files — the page a CI runner builds would otherwise differ from the page a
// developer's laptop builds, and both would be wrong for the reader.
var envDerivedDefaults = map[string]string{
	"store":    "~/.password-store",
	"identity": "",
	"theme":    theme.DefaultName,
}

// scrubEnvDerivedDefaults rewrites those defaults in place. pflag keeps
// DefValue as the string the help output shows; the bound variable is left
// alone, which is harmless here — nothing reads the config after the manual
// has been written.
func scrubEnvDerivedDefaults(root *cobra.Command) {
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		// c.Flags() includes the persistent flags inherited from the
		// parents, so one pass over the tree reaches every flag above.
		for name, def := range envDerivedDefaults {
			if f := c.Flags().Lookup(name); f != nil {
				f.DefValue = def
			}
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
}

// chmodManPages makes every generated page 0644. cobra writes them with
// os.Create, whose mode follows the builder's umask; documentation shipped
// by a package should not have permissions that depend on how the machine
// building it was configured.
func chmodManPages(root *cobra.Command, dir string) error {
	var walk func(c *cobra.Command) []string
	walk = func(c *cobra.Command) []string {
		// Mirrors the filter GenManTree applies, so the pages chmod'ed
		// are exactly the pages it wrote.
		files := []string{manPageFile(c)}
		for _, sub := range c.Commands() {
			if sub.IsAvailableCommand() && !sub.IsAdditionalHelpTopicCommand() {
				files = append(files, walk(sub)...)
			}
		}
		return files
	}
	for _, name := range walk(root) {
		// 0644, not 0600: a manual is public by definition — this is
		// what every distribution installs into /usr/share/man.
		if err := os.Chmod(filepath.Join(dir, name), 0o644); err != nil { //nolint:gosec // G302: documentation is world-readable by convention.
			return err
		}
	}
	return nil
}

// manPageFile mirrors cobra/doc's file naming, so callers can predict where
// a command's page lands without generating the tree first.
func manPageFile(c *cobra.Command) string {
	return strings.ReplaceAll(c.CommandPath(), " ", "-") + ".1"
}
