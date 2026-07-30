package cli

import (
	"fmt"

	"github.com/71g3pf4c3/binpass/pkg/store"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// newInsertCmd builds the "insert" command.
func newInsertCmd() *cobra.Command {
	var multiline, force, echo bool

	cmd := &cobra.Command{
		Use:   "insert <name>",
		Short: "Insert a new secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			st, err := openStore(cmd)
			if err != nil {
				return err
			}
			if st.Exists(name) && !force {
				return fmt.Errorf("%w: %s (use -f to overwrite)", store.ErrExists, name)
			}

			var data []byte
			if multiline {
				fmt.Fprintf(cmd.ErrOrStderr(), "Enter contents of %s and press Ctrl+D when finished:\n", name)
				data, err = readAllStdin()
				if err != nil {
					return err
				}
			} else {
				pw, err := readSecretLine(cmd, echo, fmt.Sprintf("Enter password for %s: ", name))
				if err != nil {
					return err
				}
				data = []byte(pw + "\n")
			}
			if err := st.SetRaw(name, data); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "stored %s\n", name)
			return nil
		},
	}
	cmd.Flags().BoolVarP(&multiline, "multiline", "m", false, "read multi-line secret from stdin")
	cmd.Flags().BoolVarP(&force, "force", "f", false, "overwrite existing secret")
	cmd.Flags().BoolVarP(&echo, "echo", "e", false, "echo the password as typed")
	return cmd
}

// readSecretLine reads a password from the terminal without echo (unless
// echo is set), falling back to plain stdin when not a TTY.
func readSecretLine(cmd *cobra.Command, echo bool, prompt string) (string, error) {
	if echo || !term.IsTerminal(int(syscallStdin())) {
		return readLineStdin(prompt)
	}
	fmt.Fprint(cmd.ErrOrStderr(), prompt)
	b, err := term.ReadPassword(int(syscallStdin()))
	fmt.Fprintln(cmd.ErrOrStderr())
	if err != nil {
		return "", err
	}
	return string(b), nil
}
