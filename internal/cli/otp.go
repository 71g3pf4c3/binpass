package cli

import (
	"fmt"
	"time"

	"github.com/71g3pf4c3/binpass/pkg/otp"
	"github.com/spf13/cobra"
)

// newOTPCmd builds the "otp" command and its subcommands.
func newOTPCmd() *cobra.Command {
	var clip, watch bool

	cmd := &cobra.Command{
		Use:   "otp <name>",
		Short: "Generate a one-time password from a stored secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := openStore(cmd)
			if err != nil {
				return err
			}
			sec, err := st.Get(args[0])
			if err != nil {
				return err
			}
			if len(sec.OTP) == 0 {
				return fmt.Errorf("otp: no otpauth URI in %s", args[0])
			}
			key, err := otp.Parse(sec.OTP[0])
			if err != nil {
				return err
			}

			if watch && key.Type == otp.TypeTOTP {
				return watchTOTP(cmd, key)
			}

			code, rem := key.Generate()
			if clip {
				return emit(cmd, code, true)
			}
			if key.Type == otp.TypeTOTP {
				fmt.Fprintf(cmd.OutOrStdout(), "%s (%ds)\n", code, rem)
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), code)
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&clip, "clip", "c", false, "copy code to clipboard")
	cmd.Flags().BoolVar(&watch, "watch", false, "continuously print the TOTP with countdown")

	cmd.AddCommand(newOTPAppendCmd())
	return cmd
}

// watchTOTP prints the TOTP code once per second with the remaining time.
func watchTOTP(cmd *cobra.Command, key *otp.Key) error {
	out := cmd.OutOrStdout()
	for {
		code, rem := key.Generate()
		fmt.Fprintf(out, "\r%s  %2ds remaining ", code, rem)
		time.Sleep(time.Second)
	}
}

// newOTPAppendCmd builds "otp append" to add an otpauth URI to a secret.
func newOTPAppendCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "append <name> <otpauth-uri>",
		Short: "Append an otpauth:// URI to an existing secret",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			name, uri := args[0], args[1]
			if _, err := otp.Parse(uri); err != nil {
				return err
			}
			st, err := openStore(cmd)
			if err != nil {
				return err
			}
			sec, err := st.Get(name)
			if err != nil {
				return err
			}
			sec.AddOTP(uri)
			if err := st.Set(name, sec); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "added otp URI to %s\n", name)
			return nil
		},
	}
}
