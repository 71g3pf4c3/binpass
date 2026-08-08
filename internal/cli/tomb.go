package cli

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/71g3pf4c3/binpass/pkg/tomb"
	"github.com/spf13/cobra"
)

// newTombCmd builds `binpass tomb` with its subcommands.
func newTombCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tomb init|open|close|status",
		Short: "Hide the entire password store when not in use",
		Long: `Hide the entire password store when it is not in use: no file names,
no directory structure, no metadata visible at rest.

Three backends with different trade-offs:
  coffin       Cross-platform default. Single age-encrypted tar archive.
               Works without root. Plaintext in tmpfs during session.
  luks         Linux only. dm-crypt via cryptsetup. Maximum protection.
               Requires root or polkit.
  sparsebundle macOS only. Encrypted APFS sparse bundle via hdiutil.

WARNING: shred on SSD with wear-leveling does not guarantee data destruction.
The auto-close timer and screen-lock detection mitigate the plaintext exposure
window, but cannot eliminate it entirely.`,
	}

	cmd.AddCommand(
		newTombInitCmd(app),
		newTombOpenCmd(app),
		newTombCloseCmd(app),
		newTombStatusCmd(app),
	)
	return cmd
}

// newTombInitCmd builds `binpass tomb init`.
func newTombInitCmd(app *App) *cobra.Command {
	var backend string
	var size string
	var recipient string

	cmd := &cobra.Command{
		Use:   "init [--type=coffin|luks|sparsebundle] [--size=1G] [--recipient=age1...]",
		Short: "Create an encrypted container for the password store",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return app.runTombInit(backend, size, recipient)
		},
	}
	cmd.Flags().StringVar(&backend, "type", string(tomb.DefaultBackend()), "backend: coffin, luks, or sparsebundle")
	cmd.Flags().StringVar(&size, "size", "1G", "container size (LUKS/sparsebundle only)")
	cmd.Flags().StringVarP(&recipient, "recipient", "r", "", "age recipient for the container key")
	return cmd
}

// newTombOpenCmd builds `binpass tomb open`.
func newTombOpenCmd(app *App) *cobra.Command {
	var timer string

	cmd := &cobra.Command{
		Use:   "open [--timer=1h]",
		Short: "Decrypt the container and make the store available",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			dur, err := parseDuration(timer)
			if err != nil {
				return err
			}
			return app.runTombOpen(dur)
		},
	}
	cmd.Flags().StringVar(&timer, "timer", "", "auto-close after this duration (e.g. 30m, 1h)")
	return cmd
}

// newTombCloseCmd builds `binpass tomb close`.
func newTombCloseCmd(app *App) *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "close [--force]",
		Short: "Re-encrypt the store and hide the container",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return app.runTombClose(force)
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "skip shred (overwrite-random) for faster close; data is only deleted, not overwritten")
	return cmd
}

// newTombStatusCmd builds `binpass tomb status`.
func newTombStatusCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Report whether the tomb is open or closed",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return app.runTombStatus()
		},
	}
}

// runTombInit creates an encrypted container for the store.
func (a *App) runTombInit(backend, size, recipient string) error {
	t, err := tomb.SelectBackend(tomb.Backend(backend))
	if err != nil {
		return err
	}

	// Resolve the recipient. If not given, try to read from the store's
	// existing recipients file.
	rcp := []string{recipient}
	if recipient == "" {
		rcp, err = a.tombRecipients()
		if err != nil {
			return fmt.Errorf("tomb init: specify --recipient or initialise the store first: %w", err)
		}
	}

	sizeBytes, err := parseSize(size)
	if err != nil {
		return err
	}

	if err := t.Init(a.Cfg.Dir, rcp, sizeBytes); err != nil {
		return err
	}

	fmt.Fprintf(a.Out, "Tomb initialised (%s) for %s\n", t.Name(), a.Cfg.Dir)
	return nil
}

// runTombOpen decrypts the container and starts the auto-close watcher.
func (a *App) runTombOpen(timer time.Duration) error {
	// Detect the backend from the state file, or default to coffin.
	backend := tomb.BackendCoffin
	st, _, err := a.tombStatus()
	if err == nil && st.Backend != "" {
		backend = st.Backend
	}

	t, err := tomb.SelectBackend(backend)
	if err != nil {
		return err
	}

	// Wire up identity resolution for coffin.
	if c, ok := t.(*tomb.Coffin); ok {
		c.SetIdentities(a.identities)
	}

	if err := t.Open(a.Cfg.Dir, timer); err != nil {
		if errors.Is(err, tomb.ErrAlreadyOpen) {
			fmt.Fprintf(a.Err, "Tomb is already open.\n")
			return nil
		}
		return err
	}

	fmt.Fprintf(a.Out, "Tomb opened (%s).\n", backend)

	// Start the auto-close watcher.
	watcher := tomb.NewWatcher(a.Cfg.Dir, timer, func(dir string) error {
		fmt.Fprintf(a.Err, "Auto-closing tomb...\n")
		return a.runTombClose(true)
	})

	// Block until signal or watcher closes.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	watcher.Stop()
	return nil
}

// runTombClose re-encrypts the store and hides the container.
func (a *App) runTombClose(force bool) error {
	// Detect the backend from the state file.
	backend := tomb.BackendCoffin
	st, _, err := a.tombStatus()
	if err == nil && st.Backend != "" {
		backend = st.Backend
	}

	t, err := tomb.SelectBackend(backend)
	if err != nil {
		return err
	}

	if err := t.Close(a.Cfg.Dir, force); err != nil {
		if errors.Is(err, tomb.ErrNotOpen) {
			fmt.Fprintf(a.Err, "Tomb is not open.\n")
			return nil
		}
		return err
	}

	fmt.Fprintf(a.Out, "Tomb closed.\n")
	fmt.Fprintf(a.Err, "Note: shred on SSD with wear-leveling does not guarantee data destruction.\n")
	return nil
}

// runTombStatus reports the current tomb state.
func (a *App) runTombStatus() error {
	st, isOpen, err := a.tombStatus()
	if err != nil {
		return err
	}

	if !isOpen && st.Backend == "" {
		fmt.Fprintf(a.Out, "Tomb: not initialised\n")
		return nil
	}

	state := "closed"
	if isOpen {
		state = "open"
	}
	if st.IsStale() {
		state = "stale (crash without close)"
	}

	fmt.Fprintf(a.Out, "Tomb: %s\n", state)
	fmt.Fprintf(a.Out, "  backend:  %s\n", st.Backend)
	fmt.Fprintf(a.Out, "  store:    %s\n", st.StoreDir)
	if !st.OpenedAt.IsZero() {
		fmt.Fprintf(a.Out, "  opened:   %s\n", st.OpenedAt.Format(time.RFC3339))
	}
	if st.Timer > 0 {
		fmt.Fprintf(a.Out, "  timer:    %s\n", st.Timer)
	}
	fmt.Fprintf(a.Out, "  %s\n", tomb.FormatWatcherStatus(st.Timer))
	return nil
}

// tombRecipients reads the store's recipients.
func (a *App) tombRecipients() ([]string, error) {
	s, err := a.requireStore()
	if err != nil {
		return nil, err
	}
	rcp, err := s.Recipients("")
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rcp))
	for _, r := range rcp {
		out = append(out, r.String())
	}
	return out, nil
}

// tombStatus is a helper that loads the tomb state.
func (a *App) tombStatus() (tomb.State, bool, error) {
	t, err := tomb.SelectBackend(tomb.BackendCoffin)
	if err != nil {
		return tomb.State{}, false, err
	}
	return t.Status(a.Cfg.Dir)
}

// parseDuration parses a human-friendly duration string (30m, 1h, 2h30m).
// Empty string means no timer.
func parseDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	return time.ParseDuration(s)
}

// parseSize parses a human-friendly size string (1G, 512M).
func parseSize(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	// Try as plain integer first (bytes).
	var n int64
	if _, err := fmt.Sscanf(s, "%d", &n); err == nil && n > 0 {
		return n, nil
	}
	// Suffix-based parsing.
	multipliers := map[byte]int64{
		'K': 1 << 10, 'k': 1 << 10,
		'M': 1 << 20, 'm': 1 << 20,
		'G': 1 << 30, 'g': 1 << 30,
	}
	last := s[len(s)-1]
	if mul, ok := multipliers[last]; ok {
		var base int64
		if _, err := fmt.Sscanf(s[:len(s)-1], "%d", &base); err == nil {
			return base * mul, nil
		}
	}
	return 0, fmt.Errorf("tomb: invalid size %q (use 512M, 1G, etc.)", s)
}
