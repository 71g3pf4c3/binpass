package cli

import (
	"fmt"
	"runtime"

	"github.com/71g3pf4c3/binpass/internal/version"
	"github.com/spf13/cobra"
)

// newVersionCmd builds the "version" command.
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version, commit, build date, and toolchain info",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintf(cmd.OutOrStdout(),
				"binpass %s\ncommit: %s\nbuilt:  %s\ngo:     %s\nos/arch: %s/%s\n",
				version.Version, version.Commit, version.BuildDate,
				runtime.Version(), runtime.GOOS, runtime.GOARCH)
			return nil
		},
	}
}
