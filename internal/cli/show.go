package cli

import (
	"fmt"
	"strings"

	"github.com/71g3pf4c3/binpass/pkg/otp"
	"github.com/spf13/cobra"
)

// newShowCmd builds the "show" command.
func newShowCmd() *cobra.Command {
	var clip bool
	var field string
	var qr bool

	cmd := &cobra.Command{
		Use:   "show <name>",
		Short: "Show a secret or one of its fields",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			st, err := openStore(cmd)
			if err != nil {
				return err
			}
			sec, err := st.Get(name)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()

			if field != "" {
				val, ok := sec.Get(field)
				if !ok {
					return fmt.Errorf("show: field %q not found", field)
				}
				return emit(cmd, val, clip)
			}
			if clip {
				return emit(cmd, sec.Password, true)
			}

			fmt.Fprintln(out, sec.Password)
			for _, uri := range sec.OTP {
				fmt.Fprintln(out, uri)
				if k, err := otp.Parse(uri); err == nil {
					code, rem := k.Generate()
					fmt.Fprintf(out, "  otp: %s (%ds)\n", code, rem)
				}
			}
			for _, f := range sec.Fields {
				fmt.Fprintf(out, "%s: %s\n", f.Key, f.Value)
			}
			if strings.TrimSpace(sec.Body) != "" {
				fmt.Fprintln(out, sec.Body)
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&clip, "clip", "c", false, "copy value to clipboard instead of printing")
	cmd.Flags().StringVar(&field, "field", "", "show only the given field")
	cmd.Flags().BoolVar(&qr, "qr", false, "render value as a QR code (not yet implemented)")
	return cmd
}

// emit prints value or copies it to the clipboard.
func emit(cmd *cobra.Command, value string, clip bool) error {
	if !clip {
		fmt.Fprintln(cmd.OutOrStdout(), value)
		return nil
	}
	cfg := stateOf(cmd).cfg
	if err := clipCopy(value, cfg.Clip.Timeout); err != nil {
		return err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "copied to clipboard (clears in %s)\n", cfg.Clip.Timeout)
	return nil
}
