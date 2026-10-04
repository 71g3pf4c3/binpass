package cli

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/71g3pf4c3/binpass/pkg/otp"
	"github.com/71g3pf4c3/binpass/pkg/secret"
	"github.com/71g3pf4c3/binpass/pkg/store"
	"github.com/spf13/cobra"
)

// newOTPCmd builds `binpass otp`, the native equivalent of pass-otp.
func newOTPCmd(app *App) *cobra.Command {
	var doClip, watch, showURI bool
	cmd := &cobra.Command{
		Use:   "otp [--clip,-c] [--watch] pass-name",
		Short: "Generate a one-time password from an entry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return app.runOTP(cmd.Context(), args[0], doClip, watch, showURI)
		},
	}
	cmd.Flags().BoolVarP(&doClip, "clip", "c", false, "copy the code to the clipboard")
	cmd.Flags().BoolVar(&watch, "watch", false, "keep printing codes as they roll over")
	cmd.Flags().BoolVar(&showURI, "uri", false, "print the otpauth:// URI instead of a code")
	cmd.AddCommand(newOTPCmdMenu(app))
	return cmd
}

// newOTPCmdMenu builds `binpass otp menu`: pick an entry and its code goes
// straight into the focused window, which is the whole point of a
// one-time password — by the time the user has pasted it, seconds of its
// validity are gone.
func newOTPCmdMenu(app *App) *cobra.Command {
	opts := menuOpts{launcher: "auto", field: "otp", prompt: "otp", sort: "name"}
	var doPrint, doCopy bool
	cmd := &cobra.Command{
		Use:   "menu [-- launcher-args...]",
		Short: "Pick an entry and type its one-time password",
		Long: "Lists the store in an interactive picker and sends the chosen entry's\n" +
			"current one-time password as keystrokes to the focused window.\n" +
			"Entries are not decrypted until one is chosen; the code is computed\n" +
			"and typed the moment it is picked.\n\n" +
			"--print writes the code to stdout and --copy puts it on the clipboard\n" +
			"instead of typing it. The same sorting options as `binpass menu`\n" +
			"apply, sharing one usage history.",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.args = args
			opts.typeIt = !doPrint && !doCopy
			opts.print = doPrint
			return app.runMenu(cmd.Context(), opts)
		},
	}
	cmd.Flags().StringVar(&opts.launcher, "launcher", "auto", "picker: auto|rofi|fzf|dmenu|wofi|wmenu")
	cmd.Flags().StringVar(&opts.prompt, "prompt", "otp", "picker prompt")
	cmd.Flags().StringVar(&opts.sort, "sort", "name", "list order: name, frequent, recent")
	_ = cmd.RegisterFlagCompletionFunc("sort", completeSortModes)
	cmd.Flags().BoolVar(&opts.reverse, "reverse", false, "flip the sort order")
	cmd.Flags().BoolVar(&doPrint, "print", false, "write the code to stdout instead of typing it")
	cmd.Flags().BoolVar(&doCopy, "copy", false, "copy the code to the clipboard instead of typing it")
	return cmd
}

// runOTP generates the current code for an entry.
func (a *App) runOTP(ctx context.Context, name string, doClip, watch, showURI bool) error {
	s, err := a.requireStore()
	if err != nil {
		return err
	}
	sec, err := s.Get(name)
	if err != nil {
		return err
	}
	uri, ok := sec.OTP()
	if !ok {
		return fmt.Errorf("Error: %s has no otpauth:// URI.", name) //nolint:revive,staticcheck // pass-otp's diagnostic style.
	}
	if showURI {
		fmt.Fprintln(a.Out, uri)
		return nil
	}

	cfg, err := otp.Parse(uri)
	if err != nil {
		return err
	}

	if watch {
		return a.watchOTP(ctx, cfg)
	}
	code, err := a.otpCode(s, name, sec)
	if err != nil {
		return err
	}
	return a.emitOTP(ctx, code, name, doClip)
}

// emitOTP prints or copies a generated code.
func (a *App) emitOTP(ctx context.Context, code, name string, doClip bool) error {
	if doClip {
		return a.copyToClipboard(ctx, code, name)
	}
	fmt.Fprintln(a.Out, code)
	return nil
}

// advanceHOTP rewrites the entry with the counter incremented.
func (a *App) advanceHOTP(s *store.Store, name string, sec *secret.Secret, uri string, cfg *otp.Config) error {
	updated, err := replaceCounter(sec, uri, cfg.Next().Counter)
	if err != nil {
		return err
	}
	return s.Set(name, updated)
}

// watchOTP prints a fresh code every time the current one expires, with a
// countdown, until the context is cancelled.
func (a *App) watchOTP(ctx context.Context, cfg *otp.Config) error {
	for {
		now := time.Now()
		code, err := cfg.Code(now)
		if err != nil {
			return err
		}
		expires := cfg.Expires(now)
		remaining := time.Until(expires)

		// Carriage return keeps the countdown on one line for a terminal,
		// while still emitting each code for a pipe.
		fmt.Fprintf(a.Out, "\r%s  (%2ds) ", code, int(remaining.Seconds()))

		select {
		case <-ctx.Done():
			fmt.Fprintln(a.Out)
			return nil
		case <-time.After(time.Second):
		}
	}
}

// replaceCounter returns the secret with its otpauth counter parameter set to
// n, leaving every other line untouched.
func replaceCounter(sec *secret.Secret, uri string, n uint64) (*secret.Secret, error) {
	updated, err := setURICounter(uri, n)
	if err != nil {
		return nil, err
	}
	return sec.ReplaceLineContaining(uri, updated), nil
}

// setURICounter rewrites the counter query parameter of an otpauth URI.
func setURICounter(uri string, n uint64) (string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("counter", strconv.FormatUint(n, 10))
	u.RawQuery = q.Encode()
	return u.String(), nil
}
