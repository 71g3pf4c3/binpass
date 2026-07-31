package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/71g3pf4c3/binpass/internal/config"
	"github.com/71g3pf4c3/binpass/pkg/identity"
	"github.com/spf13/cobra"
)

// newInitCmd builds the "init" command, matching `pass init [-p subfolder]
// id...`. Recipients (age/ssh) are given as positional arguments in place of
// pass's gpg-ids.
func newInitCmd() *cobra.Command {
	var recipientFlags []string
	var genIdentity bool
	var subPath string

	cmd := &cobra.Command{
		Use:   "init [--path=subfolder,-p] [--generate-identity] recipient...",
		Short: "Initialise a store or a subfolder with the given recipients",
		Long: "Initialise a new password store (or a subfolder with --path) by " +
			"writing an .age-recipients file. Recipients are age or ssh public " +
			"keys, given as arguments. With --generate-identity a new age key is " +
			"created and its recipient added automatically. Providing recipients " +
			"for an existing store re-encrypts every secret to the new set.",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := stateOf(cmd).cfg
			out := cmd.OutOrStdout()

			recipients := append([]string{}, args...)
			recipients = append(recipients, recipientFlags...)

			if genIdentity {
				rec, err := ensureIdentity(cfg.Crypto.Identity)
				if err != nil {
					return err
				}
				recipients = append(recipients, rec)
				fmt.Fprintf(out, "generated identity: %s\nrecipient: %s\n", cfg.Crypto.Identity, rec)
			}
			if len(recipients) == 0 {
				return fmt.Errorf("init: provide at least one recipient or --generate-identity")
			}

			st, err := openStore(cmd)
			if err != nil {
				return err
			}

			alreadyInit := st.Initialised()
			if subPath != "" {
				if err := st.InitSub(subPath, recipients); err != nil {
					return err
				}
				fmt.Fprintf(out, "initialised subfolder %s\n", subPath)
			} else {
				if err := st.Init(recipients); err != nil {
					return err
				}
				fmt.Fprintf(out, "initialised store at %s\n", st.Dir())
			}

			// Re-encrypt existing secrets to the new recipient set, like pass.
			if alreadyInit {
				if err := st.Reencrypt(); err != nil {
					return err
				}
				fmt.Fprintln(out, "re-encrypted existing secrets to new recipients")
			}
			return nil
		},
	}
	cmd.Flags().StringArrayVarP(&recipientFlags, "recipient", "r", nil, "additional age/ssh recipient (repeatable)")
	cmd.Flags().StringVarP(&subPath, "path", "p", "", "initialise only the given subfolder")
	cmd.Flags().BoolVar(&genIdentity, "generate-identity", false, "generate a new age identity")
	return cmd
}

// ensureIdentity returns the recipient of the identity file, creating a new
// age identity there if the file does not yet exist.
func ensureIdentity(path string) (string, error) {
	if path == "" {
		path = filepath.Join(config.ConfigDir(), "identities.age")
	}
	if data, err := os.ReadFile(path); err == nil {
		ids, err := identity.Parse(data, path)
		if err != nil {
			return "", err
		}
		if x, ok := identity.FirstX25519Recipient(ids); ok {
			return x, nil
		}
		return "", fmt.Errorf("init: identity file %s has no X25519 key", path)
	}

	id, err := identity.GenerateX25519()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	content := fmt.Sprintf("# created by binpass init\n%s\n", id.String())
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return "", fmt.Errorf("init: write identity: %w", err)
	}
	return id.Recipient().String(), nil
}
