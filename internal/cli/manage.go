package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

// newRemoveCmd builds the "rm" command, matching `pass rm [-r] [-f]`.
func newRemoveCmd() *cobra.Command {
	var recursive, force bool
	cmd := &cobra.Command{
		Use:     "rm [-r] [-f] <name>",
		Aliases: []string{"remove", "delete"},
		Short:   "Remove a secret or, with -r, a directory of secrets",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := openStore(cmd)
			if err != nil {
				return err
			}
			name := args[0]
			if recursive {
				removed, err := st.RemoveDir(name)
				if err != nil {
					return err
				}
				for _, n := range removed {
					fmt.Fprintf(cmd.OutOrStdout(), "removed %s\n", n)
				}
				return nil
			}
			if err := st.Remove(name); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "removed %s\n", name)
			return nil
		},
	}
	cmd.Flags().BoolVarP(&recursive, "recursive", "r", false, "recursively remove a directory of secrets")
	cmd.Flags().BoolVarP(&force, "force", "f", false, "do not prompt before removing")
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

// newListCmd builds the "ls" command, a pass-compatible tree listing.
func newListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "ls [subfolder]",
		Aliases: []string{"list"},
		Short:   "List secrets as a tree",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := openStore(cmd)
			if err != nil {
				return err
			}
			return listTree(cmd, st, argOrEmpty(args))
		},
	}
}

// listTree renders the store (or a subfolder) as a pass-style tree. If sub is
// an exact secret name, it is shown instead of listed.
func listTree(cmd *cobra.Command, st storeLister, sub string) error {
	names, err := st.List()
	if err != nil {
		return err
	}
	matched, exact := filterByPrefix(names, sub)
	if exact {
		// pass shows the secret when the argument names a file.
		return runShow(cmd, sub, showOptions{})
	}
	heading := "Password Store"
	if sub != "" {
		heading = strings.Trim(sub, "/")
	}
	rel := stripPrefix(matched, sub)
	renderTree(cmd.OutOrStdout(), heading, rel)
	return nil
}

// newFindCmd builds the "find" command: list secrets matching any term.
func newFindCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "find <term>...",
		Aliases: []string{"search"},
		Short:   "List secrets whose name matches any term (tree output)",
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := openStore(cmd)
			if err != nil {
				return err
			}
			names, err := st.List()
			if err != nil {
				return err
			}
			seen := map[string]bool{}
			var matched []string
			for _, term := range args {
				lower := strings.ToLower(term)
				for _, n := range names {
					if strings.Contains(strings.ToLower(n), lower) && !seen[n] {
						seen[n] = true
						matched = append(matched, n)
					}
				}
			}
			sort.Strings(matched)
			renderTree(cmd.OutOrStdout(), "Search Terms: "+strings.Join(args, ", "), matched)
			return nil
		},
	}
}

// storeLister is the minimal store surface used by listTree.
type storeLister interface {
	// List returns all secret names.
	List() ([]string, error)
}

// argOrEmpty returns the first argument or an empty string.
func argOrEmpty(args []string) string {
	if len(args) > 0 {
		return args[0]
	}
	return ""
}

// stripPrefix removes a leading "sub/" from each name for subfolder listings.
func stripPrefix(names []string, sub string) []string {
	sub = strings.Trim(sub, "/")
	if sub == "" {
		return names
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, strings.TrimPrefix(n, sub+"/"))
	}
	return out
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
