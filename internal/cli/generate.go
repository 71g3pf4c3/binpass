package cli

import (
	"fmt"
	"strconv"

	"github.com/71g3pf4c3/binpass/pkg/pwgen"
	"github.com/71g3pf4c3/binpass/pkg/store"
	"github.com/spf13/cobra"
)

// newGenerateCmd builds the "generate" command.
func newGenerateCmd() *cobra.Command {
	var noSymbols, clip, force, inPlace bool

	cmd := &cobra.Command{
		Use:   "generate <name> [length]",
		Short: "Generate and store a random password",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := stateOf(cmd).cfg
			name := args[0]
			length := cfg.Generate.Length
			if len(args) == 2 {
				n, err := strconv.Atoi(args[1])
				if err != nil {
					return fmt.Errorf("generate: invalid length %q", args[1])
				}
				length = n
			}

			st, err := openStore(cmd)
			if err != nil {
				return err
			}
			if st.Exists(name) && !force && !inPlace {
				return fmt.Errorf("%w: %s (use -f or -i)", store.ErrExists, name)
			}

			pw, err := pwgen.Generate(pwgen.Options{
				Length:  length,
				Symbols: cfg.Generate.Symbols && !noSymbols,
			})
			if err != nil {
				return err
			}

			if inPlace && st.Exists(name) {
				sec, err := st.Get(name)
				if err != nil {
					return err
				}
				sec.Password = pw
				if err := st.Set(name, sec); err != nil {
					return err
				}
			} else if err := st.SetRaw(name, []byte(pw+"\n")); err != nil {
				return err
			}

			return emit(cmd, pw, clip)
		},
	}
	cmd.Flags().BoolVarP(&noSymbols, "no-symbols", "n", false, "exclude symbols")
	cmd.Flags().BoolVarP(&clip, "clip", "c", false, "copy password to clipboard")
	cmd.Flags().BoolVarP(&force, "force", "f", false, "overwrite existing secret")
	cmd.Flags().BoolVarP(&inPlace, "in-place", "i", false, "replace only the first line of an existing secret")
	return cmd
}
