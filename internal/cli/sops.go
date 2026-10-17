package cli

import (
	"errors"
	"fmt"
	"io"

	"github.com/71g3pf4c3/binpass/internal/tui"
	"github.com/71g3pf4c3/binpass/pkg/plugin"
	"github.com/71g3pf4c3/binpass/pkg/secret"
	"github.com/71g3pf4c3/binpass/pkg/sopsfile"
	"github.com/71g3pf4c3/binpass/pkg/store"
	"github.com/spf13/cobra"
)

// newSopsCmd builds `binpass sops` with its subcommands. The group works on
// one sops-encrypted document at a time and never touches the password
// store; every subcommand takes the file as its first argument.
func newSopsCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sops edit|ls|get|set|rm FILE ...",
		Short: "Browse and edit keys of a sops-encrypted YAML or JSON file",
		Long: `Browse and edit the keys of a sops-encrypted YAML or JSON file, the
format sops-nix and similar tooling consume.

Nested maps are groups and a key is addressed as "group/sub/key". Every
operation runs the sops binary; binpass never sees master keys and a change
re-encrypts only the key it touched, so the file's git diff stays minimal.
A file that does not exist yet is created from its first key through the
project's .sops.yaml creation rules.

Requires sops 3.10 or newer on PATH.`,
		// A plugin's grant is spelled in store entry names; it has no word
		// for a sops document, so a plugin driving binpass gets no sops at
		// all rather than every file the user's keys can open.
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			if g := app.Guard(); g.Active {
				return fmt.Errorf("%w: plugin %q may not use sops; capabilities cover store entries only",
					plugin.ErrDenied, g.Name)
			}
			return nil
		},
	}
	cmd.AddCommand(
		newSopsEditCmd(app),
		newSopsListCmd(app),
		newSopsGetCmd(app),
		newSopsSetCmd(app),
		newSopsRemoveCmd(app),
	)
	return cmd
}

// newSopsEditCmd builds `binpass sops edit`.
func newSopsEditCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "edit FILE",
		Short: "Open the file's keys in the interactive TUI",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			f, err := sopsfile.Open(args[0])
			if err != nil {
				return err
			}
			code := tui.Run(tui.Options{Store: f, Cfg: app.Cfg, Standalone: true})
			if code != 0 {
				return fmt.Errorf("tui exited with code %d", code)
			}
			return nil
		},
	}
}

// newSopsListCmd builds `binpass sops ls`.
func newSopsListCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:     "ls FILE [GROUP]",
		Aliases: []string{"list"},
		Short:   "List key names, one per line",
		Args:    cobra.RangeArgs(1, 2),
		RunE: func(_ *cobra.Command, args []string) error {
			f, err := sopsfile.Open(args[0])
			if err != nil {
				return err
			}
			sub := ""
			if len(args) == 2 {
				sub = args[1]
			}
			names, err := f.List(sub)
			if err != nil {
				return err
			}
			for _, n := range names {
				fmt.Fprintln(app.Out, n)
			}
			return nil
		},
	}
}

// newSopsGetCmd builds `binpass sops get`.
func newSopsGetCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "get FILE KEY",
		Short: "Print a key's value verbatim",
		Args:  cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			f, err := sopsfile.Open(args[0])
			if err != nil {
				return err
			}
			sec, err := f.Get(args[1])
			if err != nil {
				if errors.Is(err, store.ErrNotFound) {
					return fmt.Errorf("Error: %s is not in %s.", args[1], args[0]) //nolint:revive,staticcheck // matches show's diagnostic style.
				}
				return err
			}
			// No trailing newline is added: the value may be a token a
			// consumer compares byte for byte.
			_, err = app.Out.Write(sec.Bytes())
			return err
		},
	}
}

// newSopsSetCmd builds `binpass sops set`.
func newSopsSetCmd(app *App) *cobra.Command {
	var multiline bool
	cmd := &cobra.Command{
		Use:   "set FILE KEY",
		Short: "Set a key's value from stdin or a hidden prompt",
		Long: `Set a key's value. On a terminal the value is prompted for without echo;
from a pipe stdin is stored as given. A single-line value is stored without
its line terminator, a multi-line value verbatim; editing an existing key
keeps whether or not that key ended with a newline.`,
		Args: cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			f, err := sopsfile.Open(args[0])
			if err != nil {
				return err
			}
			value, err := app.readSopsValue(args[1], multiline)
			if err != nil {
				return err
			}
			return f.Set(args[1], secret.Parse(value))
		},
	}
	cmd.Flags().BoolVarP(&multiline, "multiline", "m", false, "read the value until EOF")
	return cmd
}

// readSopsValue collects the value for `sops set`: a hidden one-line prompt
// on a terminal, the whole of stdin otherwise or when multiline is asked
// for. Pipes are read to EOF rather than to the first newline so a
// multi-line value such as a PEM key needs no flag when piped.
func (a *App) readSopsValue(key string, multiline bool) ([]byte, error) {
	_, tty := a.inputFd()
	if tty && !multiline {
		line, err := a.readSecret(fmt.Sprintf("Enter value for %s: ", key))
		if err != nil {
			return nil, err
		}
		return []byte(line), nil
	}
	if tty {
		fmt.Fprintf(a.Err, "Enter value for %s and press Ctrl+D when finished:\n\n", key)
	}
	return io.ReadAll(a.In)
}

// newSopsRemoveCmd builds `binpass sops rm`.
func newSopsRemoveCmd(app *App) *cobra.Command {
	var recursive bool
	cmd := &cobra.Command{
		Use:     "rm FILE KEY",
		Aliases: []string{"remove"},
		Short:   "Remove a key, or a whole group with --recursive",
		Args:    cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			f, err := sopsfile.Open(args[0])
			if err != nil {
				return err
			}
			if recursive {
				return f.RemoveDir(args[1])
			}
			return f.Remove(args[1])
		},
	}
	cmd.Flags().BoolVarP(&recursive, "recursive", "r", false, "remove a group and every key under it")
	return cmd
}
