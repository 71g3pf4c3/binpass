package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/71g3pf4c3/binpass/pkg/crypto"
	"github.com/spf13/cobra"
)

// recipientsFile is the store-root recipients filename.
const recipientsFile = ".age-recipients"

// newRecipientsCmd builds the "recipients" command and subcommands.
func newRecipientsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "recipients",
		Short: "Manage store recipients",
	}
	cmd.AddCommand(newRecipientsListCmd(), newRecipientsAddCmd(), newRecipientsRemoveCmd())
	return cmd
}

// rootRecipientsPath returns the path to the store-root recipients file.
func rootRecipientsPath(cmd *cobra.Command) string {
	return filepath.Join(stateOf(cmd).cfg.Store.Dir, recipientsFile)
}

// readRootRecipients reads recipient lines from the store root.
func readRootRecipients(cmd *cobra.Command) ([]string, error) {
	data, err := os.ReadFile(rootRecipientsPath(cmd))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out, nil
}

// writeRootRecipients writes recipient lines to the store root.
func writeRootRecipients(cmd *cobra.Command, recs []string) error {
	data := strings.Join(recs, "\n") + "\n"
	return os.WriteFile(rootRecipientsPath(cmd), []byte(data), 0o600)
}

// newRecipientsListCmd builds "recipients list".
func newRecipientsListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List store recipients",
		RunE: func(cmd *cobra.Command, _ []string) error {
			recs, err := readRootRecipients(cmd)
			if err != nil {
				return err
			}
			for _, r := range recs {
				fmt.Fprintln(cmd.OutOrStdout(), r)
			}
			return nil
		},
	}
}

// newRecipientsAddCmd builds "recipients add".
func newRecipientsAddCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add <recipient>...",
		Short: "Add one or more recipients (run reencrypt afterwards)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, a := range args {
				if _, err := crypto.ParseRecipient(a); err != nil {
					return err
				}
			}
			recs, err := readRootRecipients(cmd)
			if err != nil {
				return err
			}
			seen := map[string]bool{}
			for _, r := range recs {
				seen[r] = true
			}
			for _, a := range args {
				if !seen[a] {
					recs = append(recs, a)
					seen[a] = true
				}
			}
			if err := writeRootRecipients(cmd, recs); err != nil {
				return err
			}
			fmt.Fprintln(cmd.ErrOrStderr(), "recipients updated; run 'binpass reencrypt'")
			return nil
		},
	}
}

// newRecipientsRemoveCmd builds "recipients remove".
func newRecipientsRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "remove <recipient>...",
		Aliases: []string{"rm"},
		Short:   "Remove one or more recipients (run reencrypt afterwards)",
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			drop := map[string]bool{}
			for _, a := range args {
				drop[a] = true
			}
			recs, err := readRootRecipients(cmd)
			if err != nil {
				return err
			}
			var kept []string
			for _, r := range recs {
				if !drop[r] {
					kept = append(kept, r)
				}
			}
			if len(kept) == 0 {
				return fmt.Errorf("recipients: refusing to remove the last recipient")
			}
			if err := writeRootRecipients(cmd, kept); err != nil {
				return err
			}
			fmt.Fprintln(cmd.ErrOrStderr(), "recipients updated; run 'binpass reencrypt'")
			return nil
		},
	}
}
