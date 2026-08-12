package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/71g3pf4c3/binpass/pkg/keychain"
	"github.com/71g3pf4c3/binpass/pkg/secret"
	"github.com/spf13/cobra"
)

// keychainPrefix is where imported Keychain items land in the store.
const keychainPrefix = "keychain"

// newKeychainCmd builds `binpass keychain`.
func newKeychainCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keychain",
		Short: "Move secrets between the password store and the macOS Keychain",
		Long: `Move secrets between the password store and the macOS Keychain.

On macOS the system keystore cannot be replaced the way it can on Linux, so
binpass integrates with it instead: import what the Keychain already holds,
export what should also be there.

Reading a Keychain item prompts for permission, once per item, which is macOS
asking rather than binpass. A large import means a lot of prompts; --dry-run
shows what would be read without asking for anything.

macOS only.`,
	}
	cmd.AddCommand(
		newKeychainListCmd(app),
		newKeychainImportCmd(app),
		newKeychainExportCmd(app),
	)
	return cmd
}

// newKeychainListCmd builds `binpass keychain list`.
func newKeychainListCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List the Keychain items binpass can see",
		Args:    cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return app.runKeychainList()
		},
	}
}

// newKeychainImportCmd builds `binpass keychain import`.
func newKeychainImportCmd(app *App) *cobra.Command {
	var dryRun, force bool
	cmd := &cobra.Command{
		Use:   "import [SERVICE]",
		Short: "Copy Keychain items into the password store",
		Long: `Copy Keychain items into the password store under keychain/.

Without SERVICE, every generic password is imported. macOS prompts for each
one, so importing a whole Keychain means a prompt per item.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			service := ""
			if len(args) == 1 {
				service = args[0]
			}
			return app.runKeychainImport(service, dryRun, force)
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be imported without reading any secret")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite entries that already exist")
	return cmd
}

// newKeychainExportCmd builds `binpass keychain export`.
func newKeychainExportCmd(app *App) *cobra.Command {
	var service, account string
	cmd := &cobra.Command{
		Use:   "export ENTRY",
		Short: "Copy one store entry into the Keychain",
		Long: `Copy one entry from the password store into the Keychain, so that a
program which reads the Keychain can find it.

The service defaults to the entry name and the account to its username
field, if it has one.`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return app.runKeychainExport(args[0], service, account)
		},
	}
	cmd.Flags().StringVar(&service, "service", "", "Keychain service attribute (default: the entry name)")
	cmd.Flags().StringVar(&account, "account", "", "Keychain account attribute (default: the entry's username field)")
	return cmd
}

// runKeychainList prints what the Keychain holds.
func (a *App) runKeychainList() error {
	kc, err := keychain.New()
	if err != nil {
		return err
	}
	items, err := kc.List()
	if err != nil {
		return err
	}
	if len(items) == 0 {
		fmt.Fprintln(a.Out, "The Keychain holds no generic passwords.")
		return nil
	}
	for _, it := range items {
		if it.Account != "" {
			fmt.Fprintf(a.Out, "%s\t%s\n", it.Service, it.Account)
			continue
		}
		fmt.Fprintf(a.Out, "%s\n", it.Service)
	}
	return nil
}

// runKeychainImport copies Keychain items into the store.
func (a *App) runKeychainImport(service string, dryRun, force bool) error {
	s, err := a.requireStore()
	if err != nil {
		return err
	}
	kc, err := keychain.New()
	if err != nil {
		return err
	}

	items, err := kc.List()
	if err != nil {
		return err
	}
	if service != "" {
		items = filterByService(items, service)
		if len(items) == 0 {
			return fmt.Errorf("keychain: no item with service %q", service)
		}
	}

	imported, skipped := 0, 0
	for _, it := range items {
		path := keychain.StorePath(keychainPrefix, it)

		if dryRun {
			fmt.Fprintf(a.Out, "would import %s -> %s\n", describeItem(it), path)
			continue
		}
		if s.Exists(path) && !force {
			fmt.Fprintf(a.Err, "skip %s: %s already exists (use --force to overwrite)\n",
				describeItem(it), path)
			skipped++
			continue
		}

		// The secret is read one item at a time, which is what macOS prompts
		// for. Reading them all up front would ask for everything before the
		// user learned whether any of it worked.
		full, err := kc.Get(it.Service, it.Account)
		if err != nil {
			if errors.Is(err, keychain.ErrDenied) {
				fmt.Fprintf(a.Err, "skip %s: %s\n", describeItem(it), err)
				skipped++
				continue
			}
			return err
		}

		if err := s.Set(path, keychainSecret(it, full.Password)); err != nil {
			return fmt.Errorf("keychain: storing %s: %w", path, err)
		}
		imported++
	}

	if dryRun {
		fmt.Fprintf(a.Out, "\n%d item(s) would be imported.\n", len(items))
		return nil
	}
	fmt.Fprintf(a.Out, "Imported %d item(s), skipped %d.\n", imported, skipped)
	return nil
}

// runKeychainExport copies one store entry into the Keychain.
func (a *App) runKeychainExport(name, service, account string) error {
	s, err := a.requireStore()
	if err != nil {
		return err
	}
	if err := a.Guard().CheckDecrypt(name); err != nil {
		return err
	}
	kc, err := keychain.New()
	if err != nil {
		return err
	}

	sec, err := s.Get(name)
	if err != nil {
		return err
	}

	if service == "" {
		service = name
	}
	if account == "" {
		if u, ok := sec.Field("username"); ok {
			account = u
		}
	}

	if err := kc.Set(keychain.Item{
		Service:  service,
		Account:  account,
		Label:    name,
		Password: sec.Password(),
	}); err != nil {
		return err
	}

	fmt.Fprintf(a.Out, "Exported %s to the Keychain as %s.\n", name, service)
	return nil
}

// keychainSecret renders an imported item as a store entry.
//
// The Keychain attributes are kept as fields so that the entry says where it
// came from: an import that discarded them would leave a password nobody can
// match back to the account it belongs to.
func keychainSecret(it keychain.Item, password string) *secret.Secret {
	var b strings.Builder
	b.WriteString(password)
	b.WriteString("\n")
	if it.Account != "" {
		fmt.Fprintf(&b, "username: %s\n", it.Account)
	}
	fmt.Fprintf(&b, "keychain-service: %s\n", it.Service)
	if it.Label != "" && it.Label != it.Service {
		fmt.Fprintf(&b, "label: %s\n", it.Label)
	}
	return secret.Parse([]byte(b.String()))
}

// describeItem names an item for a message.
func describeItem(it keychain.Item) string {
	if it.Account != "" {
		return it.Service + " (" + it.Account + ")"
	}
	return it.Service
}

// filterByService returns the items with a given service.
func filterByService(items []keychain.Item, service string) []keychain.Item {
	var out []keychain.Item
	for _, it := range items {
		if it.Service == service {
			out = append(out, it)
		}
	}
	return out
}
