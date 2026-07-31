package cli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/71g3pf4c3/binpass/pkg/otp"
	"github.com/spf13/cobra"
)

// showOptions controls how a secret is displayed.
type showOptions struct {
	// clip, when set, copies clipLine to the clipboard instead of printing.
	clip bool
	// clipLine is the 1-based line to copy (0 means the password line).
	clipLine int
	// field, when non-empty, prints only that key/value field.
	field string
	// qr renders the value as a QR code (line qrLine).
	qr bool
	// qrLine is the 1-based line for --qr (0 means the password line).
	qrLine int
}

// newShowCmd builds the "show" command, matching `pass show`.
func newShowCmd() *cobra.Command {
	var clipFlag, qrFlag string
	var field string

	cmd := &cobra.Command{
		Use:   "show [--clip[=line],-c[line]] [--qr[=line]] [--field=name] <name>",
		Short: "Show a secret, optionally copying a line to the clipboard",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := showOptions{field: field}
			if cmd.Flags().Changed("clip") {
				opts.clip = true
				opts.clipLine = parseLineFlag(clipFlag)
			}
			if cmd.Flags().Changed("qr") {
				opts.qr = true
				opts.qrLine = parseLineFlag(qrFlag)
			}
			return runShow(cmd, args[0], opts)
		},
	}
	// -c / --clip takes an optional line number, so use a string flag whose
	// no-argument default is "1" (the password line), matching pass.
	f := cmd.Flags()
	f.StringVarP(&clipFlag, "clip", "c", "", "copy line N (default 1) to the clipboard")
	f.Lookup("clip").NoOptDefVal = "1"
	f.StringVar(&qrFlag, "qr", "", "render line N (default 1) as a QR code")
	f.Lookup("qr").NoOptDefVal = "1"
	f.StringVar(&field, "field", "", "print only the named field")
	return cmd
}

// parseLineFlag converts a --clip/--qr value to a 0-based line index (0 for
// the password line). Invalid values fall back to the password line.
func parseLineFlag(v string) int {
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return 0
	}
	return n - 1
}

// runShow displays the secret named name according to opts. It is shared by
// the show command and the bare-name default command.
func runShow(cmd *cobra.Command, name string, opts showOptions) error {
	st, err := openStore(cmd)
	if err != nil {
		return err
	}
	sec, err := st.Get(name)
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()

	// Field selection takes precedence.
	if opts.field != "" {
		val, ok := sec.Get(opts.field)
		if !ok {
			return fmt.Errorf("show: field %q not found in %s", opts.field, name)
		}
		return emit(cmd, val, opts.clip)
	}

	raw, err := st.GetRaw(name)
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")

	if opts.clip {
		line := lineAt(lines, opts.clipLine)
		return emit(cmd, line, true)
	}
	if opts.qr {
		line := lineAt(lines, opts.qrLine)
		return renderQR(cmd, line)
	}

	// Full display: password, OTP codes, fields, then body.
	fmt.Fprintln(out, sec.Password)
	for _, uri := range sec.OTP {
		fmt.Fprintln(out, uri)
		if k, err := otp.Parse(uri); err == nil {
			code, rem := k.Generate()
			fmt.Fprintf(out, "  otp: %s (%ds)\n", code, rem)
		}
	}
	for _, fld := range sec.Fields {
		fmt.Fprintf(out, "%s: %s\n", fld.Key, fld.Value)
	}
	if strings.TrimSpace(sec.Body) != "" {
		fmt.Fprintln(out, sec.Body)
	}
	return nil
}

// lineAt returns the line at index i, or the first line if out of range.
func lineAt(lines []string, i int) string {
	if i < 0 || i >= len(lines) {
		if len(lines) > 0 {
			return lines[0]
		}
		return ""
	}
	return lines[i]
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
	fmt.Fprintf(cmd.ErrOrStderr(), "Copied %s to clipboard. Will clear in %s.\n",
		"secret", cfg.Clip.Timeout)
	return nil
}
