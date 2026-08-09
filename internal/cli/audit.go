package cli

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/71g3pf4c3/binpass/pkg/audit"
	"github.com/spf13/cobra"
)

// newAuditCmd builds `binpass audit`.
func newAuditCmd(app *App) *cobra.Command {
	var (
		format   string
		parallel int
		noHIBP   bool
	)
	cmd := &cobra.Command{
		Use:   "audit [--format=FORMAT] [--parallel=N]",
		Short: "Audit the password store for weak, leaked, reused and expired passwords",
		Long: `Audit decrypts every entry and checks passwords against known
breach databases, strength metrics, reuse, and expiry.

The HIBP check uses the k-anonymity protocol: only the first 5 characters of
the SHA-1 hash leave the machine. The full password never touches the network.

Warning: audit decrypts the entire store. If your store uses a hardware token,
each entry requires a touch. Use --parallel with caution.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return app.runAudit(cmd.Context(), format, parallel, noHIBP)
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "output format: text, json")
	cmd.Flags().IntVar(&parallel, "parallel", 1, "number of concurrent decryption goroutines")
	cmd.Flags().BoolVar(&noHIBP, "no-hibp", false, "skip the HIBP breach check (offline mode)")
	return cmd
}

// runAudit performs the audit operation.
func (a *App) runAudit(ctx context.Context, format string, parallel int, noHIBP bool) error {
	s, err := a.requireStore()
	if err != nil {
		return err
	}

	if parallel > 1 {
		a.printf("Warning: parallel decryption with a hardware token will require rapid repeated touches.\n")
	}

	opts := audit.DefaultOptions()
	opts.Parallel = parallel
	if noHIBP {
		opts.HIBP = false
	}

	auditor := &audit.Auditor{
		Store:      s,
		Opts:       opts,
		HIBPClient: audit.NewHIBPClient(),
	}

	report, err := auditor.Run(ctx)
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}

	switch format {
	case "json":
		enc := json.NewEncoder(a.Out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return fmt.Errorf("audit: encoding JSON: %w", err)
		}
	case "text", "":
		a.printf("%s", audit.FormatHuman(report))
	default:
		return fmt.Errorf("audit: unknown format %q (use text or json)", format)
	}

	// Exit with non-zero if there are critical findings.
	if report.Stats.Critical > 0 {
		return fmt.Errorf("audit: %d critical finding(s)", report.Stats.Critical)
	}
	return nil
}
