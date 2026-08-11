package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// newConflictsCmd builds `binpass conflicts`.
func newConflictsCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "conflicts",
		Short: "List, inspect, and resolve synchronisation conflicts",
	}

	cmd.AddCommand(
		newConflictsListCmd(app),
		newConflictsDiffCmd(app),
		newConflictsResolveCmd(app),
	)
	return cmd
}

// newConflictsListCmd builds `binpass conflicts list`.
func newConflictsListCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Show unresolved conflict files",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return app.runConflictsList()
		},
	}
}

// newConflictsDiffCmd builds `binpass conflicts diff`.
func newConflictsDiffCmd(app *App) *cobra.Command {
	var showSecrets bool
	cmd := &cobra.Command{
		Use:   "diff CONFLICT-PATH",
		Short: "Show the differences between the local and remote versions",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return app.runConflictsDiff(args[0], showSecrets)
		},
	}
	cmd.Flags().BoolVar(&showSecrets, "show-secrets", false, "show passwords in the diff (masked by default)")
	return cmd
}

// newConflictsResolveCmd builds `binpass conflicts resolve`.
func newConflictsResolveCmd(app *App) *cobra.Command {
	var strategy string
	cmd := &cobra.Command{
		Use:   "resolve CONFLICT-PATH",
		Short: "Resolve a conflict by choosing a version",
		Long: `Resolve a synchronisation conflict. STRATEGY is one of:
  local    — keep the local version, discard the remote
  remote   — keep the remote version, discard the local
  both     — keep both files (the default at sync time)`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return app.runConflictsResolve(args[0], strategy)
		},
	}
	cmd.Flags().StringVar(&strategy, "strategy", "local", "resolution strategy: local, remote, or both")
	return cmd
}

// runConflictsList scans the store for conflict files and prints them.
// Conflict files are identified by the ".conflict-" infix in their name.
func (a *App) runConflictsList() error {
	s, err := a.requireStore()
	if err != nil {
		return err
	}
	entries, err := s.List("")
	if err != nil {
		return err
	}
	found := false
	for _, name := range entries {
		if isConflictFile(name) {
			original := conflictToOriginal(name)
			fmt.Fprintf(a.Out, "%s  (conflict of %s)\n", name, original)
			found = true
		}
	}
	if !found {
		fmt.Fprintln(a.Out, "No conflicts.")
	}
	return nil
}

// runConflictsDiff shows the differences between the two versions of a
// conflicting file. The password line is masked unless --show-secrets is set.
func (a *App) runConflictsDiff(path string, showSecrets bool) error {
	s, err := a.requireStore()
	if err != nil {
		return err
	}
	original := conflictToOriginal(path)

	localSec, lErr := s.Get(path)
	remoteSec, rErr := s.Get(original)
	if lErr != nil || rErr != nil {
		return fmt.Errorf("cannot read conflict files: local=%v remote=%v", lErr, rErr)
	}

	fmt.Fprintf(a.Out, "--- %s (local)\n", path)
	fmt.Fprintf(a.Out, "+++ %s (remote)\n", original)

	for i, line := range localSec.Lines() {
		masked := line
		if i == 0 && !showSecrets {
			masked = maskLine(line)
		}
		fmt.Fprintf(a.Out, "- %s\n", masked)
	}
	for i, line := range remoteSec.Lines() {
		masked := line
		if i == 0 && !showSecrets {
			masked = maskLine(line)
		}
		fmt.Fprintf(a.Out, "+ %s\n", masked)
	}
	return nil
}

// runConflictsResolve removes the conflict file according to the chosen
// strategy.
func (a *App) runConflictsResolve(path, strategy string) error {
	s, err := a.requireStore()
	if err != nil {
		return err
	}

	switch strategy {
	case "local":
		// Keep the local version, which means putting it back under the
		// original name. Deleting the remote copy and stopping would leave
		// the entry reachable only as "alice.conflict-thinkpad-2026...",
		// which is not what "keep the local one" means to anyone.
		original := conflictToOriginal(path)
		fmt.Fprintf(a.Out, "Resolving %s: keeping local as %s.\n", path, original)
		if s.Exists(original) {
			if err := s.Remove(original); err != nil {
				return err
			}
		}
		return s.Move(path, original)
	case "remote":
		// Keep the remote (original) file, remove the conflict.
		fmt.Fprintf(a.Out, "Resolving %s: keeping remote, removing %s.\n", originalFromConflict(path), path)
		return s.Remove(path)
	case "both":
		fmt.Fprintf(a.Out, "Both versions kept. Rename manually if needed.\n")
		return nil
	default:
		return fmt.Errorf("unknown strategy %q (use: local, remote, both)", strategy)
	}
}

// isConflictFile reports whether a store entry name is a conflict file.
func isConflictFile(name string) bool {
	return strings.Contains(name, ".conflict-")
}

// conflictToOriginal converts a conflict file name back to the original path.
// "github.com/alice.conflict-thinkpad-20260808T142233.gpg" → "github.com/alice.gpg".
func conflictToOriginal(name string) string {
	if !isConflictFile(name) {
		return name
	}
	// Find ".conflict-" and the following dash-delimited segments.
	idx := strings.Index(name, ".conflict-")
	if idx < 0 {
		return name
	}
	base := name[:idx]
	ext := ""
	if dot := strings.LastIndex(name[idx:], "."); dot > 0 {
		ext = name[idx:][dot:]
	}
	return base + ext
}

// originalFromConflict returns the original path from a conflict file name.
func originalFromConflict(name string) string {
	return conflictToOriginal(name)
}

// maskLine replaces all characters of a password line with asterisks.
func maskLine(line string) string {
	return strings.Repeat("*", len(line))
}
