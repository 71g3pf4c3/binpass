package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/71g3pf4c3/binpass/internal/config"
	"github.com/71g3pf4c3/binpass/pkg/identity"
	"github.com/spf13/cobra"
)

// newInitCmd builds the "init" command.
func newInitCmd() *cobra.Command {
	var recipients []string
	var genIdentity bool

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialise a new password store",
		Long: "Initialise a new password store by writing the root .age-recipients " +
			"file. With --generate-identity a new age key is created and its " +
			"recipient added automatically.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := stateOf(cmd).cfg
			out := cmd.OutOrStdout()

			if genIdentity {
				rec, err := ensureIdentity(cfg.Crypto.Identity)
				if err != nil {
					return err
				}
				recipients = append(recipients, rec)
				fmt.Fprintf(out, "generated identity: %s\nrecipient: %s\n", cfg.Crypto.Identity, rec)
			}
			if len(recipients) == 0 {
				return fmt.Errorf("init: provide --recipient or --generate-identity")
			}

			st, err := openStore(cmd)
			if err != nil {
				return err
			}
			if err := st.Init(recipients); err != nil {
				return err
			}
			fmt.Fprintf(out, "initialised store at %s\n", st.Dir())
			return nil
		},
	}
	cmd.Flags().StringArrayVarP(&recipients, "recipient", "r", nil, "age/ssh recipient (repeatable)")
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
