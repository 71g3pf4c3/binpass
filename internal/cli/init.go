package cli

import (
	"fmt"

	"github.com/71g3pf4c3/binpass/internal/config"
	"github.com/71g3pf4c3/binpass/pkg/crypto"
	"github.com/spf13/cobra"
)

// newInitCmd builds `binpass init`.
func newInitCmd(app *App) *cobra.Command {
	var path string
	var useAge, useGPG bool
	cmd := &cobra.Command{
		Use:   "init [--path=subfolder,-p subfolder] [--age|--gpg] gpg-id...",
		Short: "Initialise a new password store",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			var kind config.Backend
			switch {
			case useAge && useGPG:
				return fmt.Errorf("Error: choose either --age or --gpg, not both.") //nolint:revive,staticcheck // diagnostic style.
			case useAge:
				kind = config.BackendAge
				app.Cfg.Default = config.BackendAge
			case useGPG:
				kind = config.BackendGPG
				app.Cfg.Default = config.BackendGPG
			}
			return app.runInit(path, args, kind)
		},
	}
	cmd.Flags().StringVarP(&path, "path", "p", "", "initialise a subfolder only")
	cmd.Flags().BoolVar(&useAge, "age", false, "use age for this store")
	cmd.Flags().BoolVar(&useGPG, "gpg", false, "use GPG for this store")
	return cmd
}

// runInit writes the recipients file and reencrypts any existing entries for
// the new recipient set, as pass does. An explicit kind also migrates the
// entries into that backend: init --age on a gpg store that only refreshed
// recipients would leave every entry encrypted for the old ones, which the
// help text promises does not happen.
func (a *App) runInit(sub string, recipients []string, kind config.Backend) error {
	s, err := a.Store()
	if err != nil {
		return err
	}
	rcp := make([]crypto.Recipient, 0, len(recipients))
	for _, r := range recipients {
		rcp = append(rcp, crypto.Recipient(r))
	}
	existed := s.Initialised()
	if err := s.Init(sub, rcp); err != nil {
		return err
	}

	fmt.Fprintf(a.Out, "Password store initialized for %s\n", joinRecipients(rcp))
	if !existed {
		return nil
	}
	if kind != "" {
		target, err := a.cryptoFor(kind)
		if err != nil {
			return err
		}
		return s.Reencrypt(sub, target)
	}
	// An existing store must be rewritten, or the previous recipients would
	// keep their access to every entry already there.
	return s.Reencrypt(sub, nil)
}

// joinRecipients renders a recipient list the way pass prints it.
func joinRecipients(rcp []crypto.Recipient) string {
	out := ""
	for i, r := range rcp {
		if i > 0 {
			out += ", "
		}
		out += r.String()
	}
	return out
}
