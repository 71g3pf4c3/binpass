package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// newRemoveCmd builds `binpass rm`.
func newRemoveCmd(app *App) *cobra.Command {
	var recursive, force bool
	cmd := &cobra.Command{
		Use:     "rm [--recursive,-r] [--force,-f] pass-name",
		Aliases: []string{"remove", "delete"},
		Short:   "Remove an existing password or directory",
		Args:    cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return app.runRemove(args[0], recursive, force)
		},
	}
	cmd.Flags().BoolVarP(&recursive, "recursive", "r", false, "remove a directory and its contents")
	cmd.Flags().BoolVarP(&force, "force", "f", false, "remove without prompting")
	return cmd
}

// runRemove deletes an entry or, with --recursive, a whole subfolder.
func (a *App) runRemove(name string, recursive, force bool) error {
	s, err := a.requireStore()
	if err != nil {
		return err
	}
	// Deleting is a write, and the destructive kind: a plugin scoped to
	// read must not be able to empty the store.
	if err := a.Guard().CheckWrite(name); err != nil {
		return err
	}
	isDir := s.IsDir(name)
	if isDir && !recursive {
		return fmt.Errorf("Error: %s is a directory.", name) //nolint:revive,staticcheck // pass's exact wording.
	}
	if !isDir && !s.Exists(name) {
		return fmt.Errorf("Error: %s is not in the password store.", name) //nolint:revive,staticcheck // pass's exact wording.
	}
	if !force {
		what := "password"
		if isDir {
			what = "directory"
		}
		ok, err := a.confirm(fmt.Sprintf("Are you sure you would like to delete %s %s?", what, name))
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
	}
	if isDir {
		return s.RemoveDir(name)
	}
	return s.Remove(name)
}

// newMoveCmd builds `binpass mv`.
func newMoveCmd(app *App) *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:     "mv [--force,-f] old-path new-path",
		Aliases: []string{"rename"},
		Short:   "Rename or move a password, reencrypting as needed",
		Args:    cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			return app.runTransfer(args[0], args[1], force, true)
		},
	}
	cmd.Flags().BoolVarP(&force, "force", "f", false, "overwrite without prompting")
	return cmd
}

// newCopyCmd builds `binpass cp`.
func newCopyCmd(app *App) *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:     "cp [--force,-f] old-path new-path",
		Aliases: []string{"copy"},
		Short:   "Copy a password, reencrypting as needed",
		Args:    cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			return app.runTransfer(args[0], args[1], force, false)
		},
	}
	cmd.Flags().BoolVarP(&force, "force", "f", false, "overwrite without prompting")
	return cmd
}

// runTransfer implements both mv and cp.
func (a *App) runTransfer(from, to string, force, remove bool) error {
	s, err := a.requireStore()
	if err != nil {
		return err
	}
	if !s.Exists(from) && !s.IsDir(from) {
		return fmt.Errorf("Error: %s is not in the password store.", from) //nolint:revive,staticcheck // pass's exact wording.
	}
	if !force && s.Exists(to) {
		ok, err := a.confirm(fmt.Sprintf("An entry already exists for %s. Overwrite it?", to))
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
	}
	if remove {
		return s.Move(from, to)
	}
	return s.Copy(from, to)
}
