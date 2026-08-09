package cli

import (
	"fmt"

	"github.com/71g3pf4c3/binpass/pkg/tomb"
	"github.com/spf13/cobra"
)

// newDoctorCmd builds `binpass doctor`, which runs health checks and prints
// a diagnostic report.
func newDoctorCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Run health checks and show diagnostics",
		Long: `Run health checks for the password store environment:

  - Tomb watcher capabilities (D-Bus screen lock, suspend, timer)
  - Stale state detection (crash recovery)

This is a read-only diagnostic command; it does not modify the store.`,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return app.runDoctor()
		},
	}
}

func (a *App) runDoctor() error {
	// Tomb watcher health.
	fmt.Fprintf(a.Out, "[tomb] %s\n", tomb.DoctorCheck())

	// Stale state check.
	st, err := tomb.SelectBackend(tomb.BackendCoffin)
	if err != nil {
		fmt.Fprintf(a.Err, "[tomb] error selecting backend: %v\n", err)
		return nil
	}
	state, isOpen, err := st.Status(a.Cfg.Dir)
	if err != nil {
		fmt.Fprintf(a.Err, "[tomb] error reading state: %v\n", err)
		return nil
	}
	if state.Backend == "" {
		fmt.Fprintf(a.Out, "[tomb] not initialised\n")
		return nil
	}
	if state.IsStale() {
		fmt.Fprintf(a.Out, "[tomb] stale state detected (PID %d is dead, tomb was not closed cleanly)\n", state.PID)
	} else if isOpen {
		fmt.Fprintf(a.Out, "[tomb] open (backend: %s, PID: %d)\n", state.Backend, state.PID)
	} else {
		fmt.Fprintf(a.Out, "[tomb] closed (backend: %s)\n", state.Backend)
	}

	return nil
}
