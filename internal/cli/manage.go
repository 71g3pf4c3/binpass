package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// newRemoveCmd builds the "rm" command.
func newRemoveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "rm <name>",
		Aliases: []string{"remove", "delete"},
		Short:   "Remove a secret",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := openStore(cmd)
			if err != nil {
				return err
			}
			if err := st.Remove(args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "removed %s\n", args[0])
			return nil
		},
	}
	return cmd
}

// newMoveCmd builds the "mv" command.
func newMoveCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:     "mv <src> <dst>",
		Aliases: []string{"rename"},
		Short:   "Move/rename a secret, re-encrypting to the destination recipients",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := openStore(cmd)
			if err != nil {
				return err
			}
			if err := st.Move(args[0], args[1], force); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "moved %s -> %s\n", args[0], args[1])
			return nil
		},
	}
	cmd.Flags().BoolVarP(&force, "force", "f", false, "overwrite existing destination")
	return cmd
}

// newCopyCmd builds the "cp" command.
func newCopyCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:     "cp <src> <dst>",
		Aliases: []string{"copy"},
		Short:   "Copy a secret, re-encrypting to the destination recipients",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := openStore(cmd)
			if err != nil {
				return err
			}
			if err := st.Copy(args[0], args[1], force); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "copied %s -> %s\n", args[0], args[1])
			return nil
		},
	}
	cmd.Flags().BoolVarP(&force, "force", "f", false, "overwrite existing destination")
	return cmd
}

// newListCmd builds the "ls" command.
func newListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "ls",
		Aliases: []string{"list"},
		Short:   "List all secrets",
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := openStore(cmd)
			if err != nil {
				return err
			}
			names, err := st.List()
			if err != nil {
				return err
			}
			for _, n := range names {
				fmt.Fprintln(cmd.OutOrStdout(), n)
			}
			return nil
		},
	}
}

// newFindCmd builds the "find" command.
func newFindCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "find <term>",
		Aliases: []string{"search"},
		Short:   "Find secrets whose name contains a term",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := openStore(cmd)
			if err != nil {
				return err
			}
			names, err := st.Find(args[0])
			if err != nil {
				return err
			}
			for _, n := range names {
				fmt.Fprintln(cmd.OutOrStdout(), n)
			}
			return nil
		},
	}
}

// newGrepCmd builds the "grep" command.
func newGrepCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "grep <term>",
		Short: "Search decrypted secret contents for a term",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := openStore(cmd)
			if err != nil {
				return err
			}
			matches, err := st.Grep(args[0])
			if err != nil {
				return err
			}
			for _, m := range matches {
				fmt.Fprintf(cmd.OutOrStdout(), "%s: %s\n", m.Name, m.Line)
			}
			return nil
		},
	}
}
