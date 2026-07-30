package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// newReencryptCmd builds the "reencrypt" command.
func newReencryptCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reencrypt",
		Short: "Re-encrypt every secret to the current recipients",
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := openStore(cmd)
			if err != nil {
				return err
			}
			if err := st.Reencrypt(); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "reencrypted all secrets")
			return nil
		},
	}
}
