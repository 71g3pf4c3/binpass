package cli

import (
	"fmt"

	"github.com/71g3pf4c3/binpass/internal/config"
	"github.com/71g3pf4c3/binpass/pkg/sync"
	"github.com/spf13/cobra"
)

// newFsckCmd builds `binpass fsck`.
func newFsckCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fsck",
		Short: "Check password store consistency",
		Long: `Verify that the password store, the sync state database, and the
recipient files are consistent. Reports untracked files, orphaned state
entries, size drift, and missing recipients.`,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return app.runFsck()
		},
	}
	return cmd
}

// runFsck checks the consistency of the password store against state.db.
func (a *App) runFsck() error {
	storeDir := a.Cfg.Dir
	stateDir := config.StateDir()

	db, err := sync.OpenStateDB(stateDir)
	if err != nil {
		return fmt.Errorf("fsck: open state db: %w", err)
	}
	defer db.Close()

	results, err := sync.Fsck(storeDir, stateDir, db)
	if err != nil {
		return fmt.Errorf("fsck: %w", err)
	}

	if len(results) == 0 {
		fmt.Fprintln(a.Out, "Store is consistent. No issues found.")
		return nil
	}

	errCount := 0
	warnCount := 0
	for _, r := range results {
		switch r.Severity {
		case "error":
			errCount++
			fmt.Fprintf(a.Err, "ERROR: %s: %s\n", r.Path, r.Issue)
		case "warning":
			warnCount++
			fmt.Fprintf(a.Out, "WARNING: %s: %s\n", r.Path, r.Issue)
		}
	}

	fmt.Fprintf(a.Out, "\n%d error(s), %d warning(s)\n", errCount, warnCount)

	if errCount > 0 {
		return fmt.Errorf("fsck: %d error(s) found", errCount)
	}
	return nil
}
