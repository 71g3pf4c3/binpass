package cli

import (
	"fmt"
	"time"

	"github.com/71g3pf4c3/binpass/pkg/vcs"
	"github.com/spf13/cobra"
)

// newHistoryCmd builds `binpass history`, which shows the git log for a
// single entry with masked passwords and a field-level diff between
// consecutive versions.
func newHistoryCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "history pass-name",
		Short: "List the git revisions of an entry",
		Long: `List every git revision that touched an entry, newest first.

Only commit metadata is shown. Diffing two revisions means decrypting the
ciphertext as it was at each commit, which cannot be done from the working
tree alone: an old revision may be encrypted to recipients that no longer
exist there. Until that is implemented the printed git command shows the
raw diff.

Nothing here decrypts anything, so no password can be revealed by it.`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return app.runHistory(args[0])
		},
	}
	return cmd
}

// runHistory displays the git history for a single entry.
func (a *App) runHistory(name string) error {
	s, err := a.requireStore()
	if err != nil {
		return err
	}

	backend := vcs.DetectBackend(s.Dir())
	commits, err := backend.Log(name, vcs.LogOption{})
	if err != nil {
		return err
	}
	if len(commits) == 0 {
		return fmt.Errorf("binpass: %s has no git history", name)
	}

	for _, c := range commits {
		fmt.Fprintf(a.Out, "%s  %s  %s\n", c.Hash, c.Date.Format(time.DateTime), c.Subject)
	}

	// A field-level diff would have to decrypt the ciphertext as it stood at
	// each commit, which the working tree alone cannot do: an old revision
	// may be encrypted to recipients that are no longer present. Until that
	// exists, point at the command that shows the raw diff.
	fmt.Fprintf(a.Err, "\nShowing %d revision(s). For the full diff:\n  git -C %s log -p -- %s.gpg %s.age\n",
		len(commits), s.Dir(), name, name)

	return nil
}
