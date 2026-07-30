// Package cli implements the binpass command-line interface as a cobra
// command tree. Commands are thin: they parse flags, invoke pkg/store, and
// format output. Business logic lives in the pkg/* packages.
package cli

import (
	"context"
	"fmt"

	"github.com/71g3pf4c3/binpass/internal/config"
	"github.com/71g3pf4c3/binpass/pkg/crypto"
	"github.com/71g3pf4c3/binpass/pkg/identity"
	"github.com/71g3pf4c3/binpass/pkg/store"
	"github.com/spf13/cobra"
)

// appState carries resolved config across commands via cobra context.
type appState struct {
	// cfg is the loaded configuration.
	cfg *config.Config
}

// stateKey is the context key type for appState.
type stateKey struct{}

// NewRootCmd builds the root binpass command.
func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "binpass",
		Short:         "binpass — age-based password manager, drop-in for pass/gopass",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(cmd)
			if err != nil {
				return fmt.Errorf("config: %w", err)
			}
			ctx := context.WithValue(cmd.Context(), stateKey{}, &appState{cfg: cfg})
			cmd.SetContext(ctx)
			return nil
		},
	}

	pf := root.PersistentFlags()
	pf.String("store", "", "password store directory")
	pf.String("config", "", "config file path")
	pf.String("log-level", "", "log level (debug|info|warn|error)")
	_ = pf.Lookup("store")

	root.AddCommand(
		newVersionCmd(),
		newInitCmd(),
		newInsertCmd(),
		newShowCmd(),
		newEditCmd(),
		newGenerateCmd(),
		newRemoveCmd(),
		newMoveCmd(),
		newCopyCmd(),
		newListCmd(),
		newFindCmd(),
		newGrepCmd(),
		newOTPCmd(),
		newCardCmd(),
		newRecipientsCmd(),
		newReencryptCmd(),
		newCompletionCmd(root),
	)
	return root
}

// stateOf extracts the appState from the command context.
func stateOf(cmd *cobra.Command) *appState {
	s, _ := cmd.Context().Value(stateKey{}).(*appState)
	return s
}

// openStore builds a Store from config, loading identities when available.
func openStore(cmd *cobra.Command) (*store.Store, error) {
	cfg := stateOf(cmd).cfg
	c, err := loadCrypto(cfg)
	if err != nil {
		return nil, err
	}
	return store.New(cfg.Store.Dir, c), nil
}

// loadCrypto assembles an age Crypto with identities from the config path.
// Missing identity files are tolerated for encrypt-only operations.
func loadCrypto(cfg *config.Config) (crypto.Crypto, error) {
	loaded, err := identity.LoadFile(cfg.Crypto.Identity)
	if err != nil {
		// Encrypt-only paths (insert/generate) still work without identities.
		return crypto.NewAge(nil), nil
	}
	return crypto.NewAge(loaded), nil
}
