package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/71g3pf4c3/binpass/internal/config"
	"github.com/71g3pf4c3/binpass/pkg/secretservice"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// newSSCmd builds `binpass ss`, the Secret Service provider.
func newSSCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ss",
		Short: "Serve the password store as the system keyring (org.freedesktop.secrets)",
		Long: `Serve the password store over the Secret Service API, so that programs
which already use the system keyring — Chrome, VS Code, NetworkManager,
Evolution — read their secrets from your password store without knowing it
exists.

Items are stored as ordinary pass entries under secret-service/ and remain
readable with binpass show. Their attributes are kept inside the encrypted
file, with lookup going through an index of keyed hashes, so a sync provider
never sees which hosts and usernames you have accounts for.

Linux only: the API is a freedesktop D-Bus interface.`,
	}
	cmd.AddCommand(
		newSSServeCmd(app),
		newSSDoctorCmd(app),
		newSSReindexCmd(app),
	)
	return cmd
}

// newSSServeCmd builds `binpass ss serve`.
func newSSServeCmd(app *App) *cobra.Command {
	var takeover string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the Secret Service provider until interrupted",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return app.runSSServe(cmd.Context(), takeover)
		},
	}
	cmd.Flags().StringVar(&takeover, "takeover", "refuse",
		"what to do when another provider owns the bus name: refuse, wait, or replace")
	return cmd
}

// newSSDoctorCmd builds `binpass ss doctor`.
func newSSDoctorCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Report who owns the keyring bus name and what to do about it",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return app.runSSDoctor()
		},
	}
}

// newSSReindexCmd builds `binpass ss reindex`.
func newSSReindexCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "reindex",
		Short: "Rebuild the attribute index from the items on disk",
		Long: `Rebuild the index used to look items up by attribute.

Needed after a sync brings items in from another machine, and as the repair
for an index that has drifted from the store for any other reason: the items
are the truth, and the index is derived from them.`,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return app.runSSReindex()
		},
	}
}

// runSSServe runs the provider until the process is interrupted.
func (a *App) runSSServe(ctx context.Context, takeover string) error {
	s, err := a.requireStore()
	if err != nil {
		return err
	}

	seed, err := a.ssIndexSeed()
	if err != nil {
		return err
	}

	cfg, err := loadSSConfig()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(a.Err, "Serving %s on the session bus. Press Ctrl-C to stop.\n", secretservice.BusName)

	err = secretservice.Serve(ctx, secretservice.ServeOptions{
		Store:     s,
		IndexSeed: seed,
		Policy:    cfg,
		Takeover:  secretservice.Takeover(takeover),
		Notify:    os.Stderr,
	})
	if errors.Is(err, secretservice.ErrNameTaken) {
		// The overwhelmingly common cause is gnome-keyring, and a bare
		// "name taken" leaves the user to work that out themselves.
		return fmt.Errorf("%w\n\nRun `binpass ss doctor` to see who has it", err)
	}
	return err
}

// runSSDoctor reports who owns the bus name.
func (a *App) runSSDoctor() error {
	owner, taken, err := secretservice.Owner()
	if err != nil {
		return err
	}

	if !taken {
		fmt.Fprintf(a.Out, "%s: free\n", secretservice.BusName)
		fmt.Fprintf(a.Out, "\nStart the provider with:\n  binpass ss serve\n")
		return nil
	}

	fmt.Fprintf(a.Out, "%s: owned by %s\n", secretservice.BusName, owner)
	fmt.Fprintf(a.Out, `
Only one program can own that name, so binpass cannot start while it is held.

If that is gnome-keyring, stop it from taking the name at login:

  systemctl --user mask gnome-keyring-daemon.socket
  systemctl --user stop gnome-keyring-daemon.service

For KWallet:

  systemctl --user mask plasma-kwallet-pam.service

Then start binpass:

  binpass ss serve

Or take the name from whoever holds it, for this session only:

  binpass ss serve --takeover=replace
`)
	return nil
}

// runSSReindex rebuilds the attribute index.
func (a *App) runSSReindex() error {
	s, err := a.requireStore()
	if err != nil {
		return err
	}
	seed, err := a.ssIndexSeed()
	if err != nil {
		return err
	}

	n, err := secretservice.NewStore(s, seed).Reindex()
	if err != nil {
		return err
	}
	fmt.Fprintf(a.Out, "Indexed %d item(s).\n", n)
	return nil
}

// ssIndexSeed returns the seed the attribute index key is derived from.
//
// It has to be the same on every machine the store is synchronised to, or
// each would compute different hashes and an index arriving from elsewhere
// would match nothing. The store's recipients satisfy that: they travel with
// the store, and they are not secret — the index key is derived from them
// through an HMAC, and its security rests on the derivation rather than on
// the seed being hidden.
func (a *App) ssIndexSeed() ([]byte, error) {
	s, err := a.requireStore()
	if err != nil {
		return nil, err
	}
	rcp, err := s.Recipients("")
	if err != nil {
		return nil, fmt.Errorf("ss: reading the store's recipients: %w", err)
	}
	if len(rcp) == 0 {
		return nil, errors.New("ss: the store has no recipients; run `binpass init` first")
	}
	var seed []byte
	for _, r := range rcp {
		seed = append(seed, r.String()...)
		seed = append(seed, 0)
	}
	return seed, nil
}

// ssConfigPath returns the path of the access policy file.
func ssConfigPath() string {
	if p := os.Getenv("BINPASS_SS_CONFIG"); p != "" {
		return p
	}
	return filepath.Join(filepath.Dir(config.FilePath()), "secret-service.yaml")
}

// loadSSConfig reads the access policy, falling back to the default when
// there is no file. A missing policy is not an error: the provider is usable
// with no configuration at all.
func loadSSConfig() (secretservice.Config, error) {
	cfg := secretservice.DefaultConfig()

	data, err := os.ReadFile(ssConfigPath()) //nolint:gosec // a path binpass derives from its own config location.
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("ss: reading %s: %w", ssConfigPath(), err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("ss: parsing %s: %w", ssConfigPath(), err)
	}
	return cfg, nil
}
