package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/71g3pf4c3/binpass/pkg/clip"
	"github.com/71g3pf4c3/binpass/pkg/store"
	"github.com/spf13/cobra"
)

// showOpts holds the parsed flags of `binpass show`.
type showOpts struct {
	// name is the entry to display.
	name string
	// clip requests the clipboard instead of stdout.
	clip bool
	// qrcode requests a QR code instead of stdout.
	qrcode bool
	// line is the 1-based line to copy or encode.
	line int
	// field names a "key: value" field to print instead of the whole entry.
	field string
}

// newShowCmd builds `binpass show`.
func newShowCmd(app *App) *cobra.Command {
	opts := showOpts{line: 1}
	cmd := &cobra.Command{
		Use:   "show [--clip[=line-number],-c[line-number]] pass-name",
		Short: "Show existing password",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				opts.name = args[0]
			}
			opts.clip = cmd.Flags().Changed("clip")
			opts.qrcode = cmd.Flags().Changed("qrcode")
			if opts.clip && opts.qrcode {
				return errors.New("Usage: binpass show [--clip[=line-number],-c[line-number]] [--qrcode[=line-number],-q[line-number]] [pass-name]") //nolint:revive,staticcheck // pass's exact wording.
			}
			return app.runShow(cmd.Context(), opts)
		},
	}
	cmd.Flags().IntVarP(&opts.line, "clip", "c", 1, "copy the given line to the clipboard")
	cmd.Flags().IntVarP(&opts.line, "qrcode", "q", 1, "render the given line as a QR code")
	cmd.Flags().StringVar(&opts.field, "field", "", "print a single named field")
	cmd.Flags().Lookup("clip").NoOptDefVal = "1"
	cmd.Flags().Lookup("qrcode").NoOptDefVal = "1"
	return cmd
}

// runShow prints an entry, or lists a subfolder when the name is a directory,
// which is how pass makes `pass foo` work for both.
func (a *App) runShow(ctx context.Context, opts showOpts) error {
	s, err := a.requireStore()
	if err != nil {
		return err
	}

	sec, err := s.Get(opts.name)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			if s.IsDir(opts.name) {
				return a.runList(ctx, opts.name)
			}
			return fmt.Errorf("Error: %s is not in the password store.", opts.name) //nolint:revive,staticcheck // pass's exact wording.
		}
		return err
	}

	if opts.field != "" {
		// "password" names the first line, which has no key of its own but
		// is the field scripts ask for most.
		value := sec.Password()
		if opts.field != "password" {
			v, ok := sec.Field(opts.field)
			if !ok {
				return fmt.Errorf("Error: %s has no field %q.", opts.name, opts.field) //nolint:revive,staticcheck // matches pass's diagnostic style.
			}
			value = v
		}
		if opts.clip {
			return a.copyToClipboard(ctx, value, opts.name)
		}
		fmt.Fprintln(a.Out, value)
		return nil
	}

	if !opts.clip && !opts.qrcode {
		// The plaintext is written verbatim: pass round-trips it through
		// base64 precisely to avoid mangling entries without a final newline.
		_, err := a.Out.Write(sec.Bytes())
		return err
	}

	line, err := selectLine(sec.Lines(), opts.line)
	if err != nil {
		return err
	}
	if opts.qrcode {
		return a.renderQR(line)
	}
	return a.copyToClipboard(ctx, line, opts.name)
}

// selectLine returns the 1-based line n, with pass's diagnostic when absent.
func selectLine(lines []string, n int) (string, error) {
	if n < 1 {
		return "", fmt.Errorf("Clip location '%d' is not a number.", n) //nolint:revive,staticcheck // pass's exact wording.
	}
	if n > len(lines) || strings.TrimSpace(lines[n-1]) == "" {
		return "", fmt.Errorf("There is no password to put on the clipboard at line %d.", n) //nolint:revive,staticcheck // pass's exact wording.
	}
	return lines[n-1], nil
}

// copyToClipboard puts text on the clipboard and clears it after the
// configured timeout.
func (a *App) copyToClipboard(ctx context.Context, text, name string) error {
	backend, err := clip.Detect(a.Cfg.XSelection)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.Err, "Copied %s to clipboard. Will clear in %d seconds.\n", name, int(a.Cfg.ClipTime.Seconds()))
	return clip.CopyWithTimeout(ctx, backend, text, a.Cfg.ClipTime)
}
