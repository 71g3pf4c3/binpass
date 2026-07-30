package cli

import (
	"fmt"

	"github.com/71g3pf4c3/binpass/pkg/secret"
	"github.com/71g3pf4c3/binpass/pkg/store"
	"github.com/spf13/cobra"
)

// cardFields is the ordered set of prompts for a bank card.
var cardFields = []string{"Bank", "Number", "Holder", "Expires", "CVV"}

// newCardCmd builds the "card" command and its subcommands.
func newCardCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "card",
		Short: "Manage typed bank-card secrets",
	}
	cmd.AddCommand(newCardAddCmd(), newCardShowCmd())
	return cmd
}

// newCardAddCmd builds "card add".
func newCardAddCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Add a bank card, prompting for each field",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			st, err := openStore(cmd)
			if err != nil {
				return err
			}
			if st.Exists(name) && !force {
				return fmt.Errorf("%w: %s (use -f)", store.ErrExists, name)
			}

			sec := &secret.Secret{Kind: secret.KindCard}
			for _, field := range cardFields {
				val, err := readLineStdin(fmt.Sprintf("%s: ", field))
				if err != nil {
					return err
				}
				sec.Set(field, val)
			}
			if err := st.Set(name, sec); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "stored card %s\n", name)
			return nil
		},
	}
	cmd.Flags().BoolVarP(&force, "force", "f", false, "overwrite existing card")
	return cmd
}

// newCardShowCmd builds "card show".
func newCardShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Show a stored bank card",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := openStore(cmd)
			if err != nil {
				return err
			}
			sec, err := st.Get(args[0])
			if err != nil {
				return err
			}
			if sec.Kind != secret.KindCard {
				return fmt.Errorf("card: %s is not a card (type=%s)", args[0], sec.Kind)
			}
			out := cmd.OutOrStdout()
			for _, f := range sec.Fields {
				fmt.Fprintf(out, "%s: %s\n", f.Key, f.Value)
			}
			return nil
		},
	}
}
