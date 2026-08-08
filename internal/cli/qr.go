package cli

import (
	"fmt"

	qrcode "github.com/skip2/go-qrcode"
)

// renderQR prints text as a QR code on the terminal, so that a secret can be
// moved to a phone without it ever touching the network.
func (a *App) renderQR(text string) error {
	q, err := qrcode.New(text, qrcode.Medium)
	if err != nil {
		return err
	}
	fmt.Fprint(a.Out, q.ToSmallString(false))
	return nil
}
