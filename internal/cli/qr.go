package cli

import (
	"fmt"

	qrcode "github.com/skip2/go-qrcode"
	"github.com/spf13/cobra"
)

// renderQR prints a terminal-friendly QR code of text to stdout.
func renderQR(cmd *cobra.Command, text string) error {
	if text == "" {
		return fmt.Errorf("qr: nothing to encode")
	}
	q, err := qrcode.New(text, qrcode.Medium)
	if err != nil {
		return fmt.Errorf("qr: %w", err)
	}
	fmt.Fprint(cmd.OutOrStdout(), q.ToSmallString(false))
	return nil
}
