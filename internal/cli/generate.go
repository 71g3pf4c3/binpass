package cli

import (
	"context"
	"fmt"
	"strconv"

	"github.com/71g3pf4c3/binpass/pkg/pwgen"
	"github.com/71g3pf4c3/binpass/pkg/secret"
	"github.com/spf13/cobra"
)

// generateOpts holds the parsed flags of `binpass generate`.
type generateOpts struct {
	// noSymbols restricts the alphabet to alphanumerics.
	noSymbols bool
	// clip copies the result instead of printing it.
	clip bool
	// inPlace replaces only the first line of an existing entry.
	inPlace bool
	// force overwrites without prompting.
	force bool
	// words, when positive, generates a diceware passphrase instead.
	words int
	// separator joins passphrase words.
	separator string
}

// newGenerateCmd builds `binpass generate`.
func newGenerateCmd(app *App) *cobra.Command {
	var opts generateOpts
	cmd := &cobra.Command{
		Use:   "generate [--no-symbols,-n] [--clip,-c] [--in-place,-i | --force,-f] pass-name [pass-length]",
		Short: "Generate a new password",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			length := app.Cfg.GeneratedLength
			if len(args) == 2 {
				n, err := strconv.Atoi(args[1])
				if err != nil || n <= 0 {
					return fmt.Errorf("Error: pass-length %q must be a number.", args[1]) //nolint:revive,staticcheck // pass's diagnostic style.
				}
				length = n
			}
			return app.runGenerate(cmd.Context(), args[0], length, opts)
		},
	}
	cmd.Flags().BoolVarP(&opts.noSymbols, "no-symbols", "n", false, "generate without symbols")
	cmd.Flags().BoolVarP(&opts.clip, "clip", "c", false, "copy to the clipboard instead of printing")
	cmd.Flags().BoolVarP(&opts.inPlace, "in-place", "i", false, "replace only the first line")
	cmd.Flags().BoolVarP(&opts.force, "force", "f", false, "overwrite without prompting")
	cmd.Flags().IntVar(&opts.words, "words", 0, "generate a diceware passphrase of N words")
	cmd.Flags().StringVar(&opts.separator, "separator", "-", "word separator for passphrases")
	return cmd
}

// runGenerate creates a password, stores it, and reports it.
func (a *App) runGenerate(ctx context.Context, name string, length int, opts generateOpts) error {
	s, err := a.requireStore()
	if err != nil {
		return err
	}
	if err := a.Guard().CheckWrite(name); err != nil {
		return err
	}
	exists := s.Exists(name)
	if exists && !opts.force && !opts.inPlace {
		ok, err := a.confirm(fmt.Sprintf("An entry already exists for %s. Overwrite it?", name))
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
	}

	password, err := a.generatePassword(length, opts)
	if err != nil {
		return err
	}

	// --in-place keeps everything below the first line, so the OTP URI and
	// the notes attached to an entry survive a rotation.
	sec := secret.New(password, "")
	if opts.inPlace && exists {
		existing, err := s.Get(name)
		if err != nil {
			return err
		}
		existing.SetPassword(password)
		sec = existing
	}
	if err := s.Set(name, sec); err != nil {
		return err
	}

	if opts.clip {
		return a.copyToClipboard(ctx, password, name)
	}
	fmt.Fprintf(a.Out, "The generated password for %s is:\n%s\n", name, password)
	return nil
}

// generatePassword produces a password or passphrase per opts.
func (a *App) generatePassword(length int, opts generateOpts) (string, error) {
	if opts.words > 0 {
		return pwgen.Passphrase(opts.words, pwgen.EFFLarge(), opts.separator)
	}
	alphabet := a.Cfg.CharacterSet
	if opts.noSymbols {
		alphabet = a.Cfg.CharacterSetNoSymbols
	}
	return pwgen.Generate(length, alphabet)
}
