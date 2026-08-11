package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/71g3pf4c3/binpass/pkg/secret"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// newInsertCmd builds `binpass insert`.
func newInsertCmd(app *App) *cobra.Command {
	var multiline, echo, force bool
	cmd := &cobra.Command{
		Use:   "insert [--echo,-e | --multiline,-m] [--force,-f] pass-name",
		Short: "Insert a new password",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if multiline && echo {
				return errors.New("Usage: binpass insert [--echo,-e | --multiline,-m] [--force,-f] pass-name") //nolint:revive,staticcheck // pass's exact wording.
			}
			return app.runInsert(cmd.Context(), args[0], multiline, echo, force)
		},
	}
	cmd.Flags().BoolVarP(&multiline, "multiline", "m", false, "read the entry until EOF")
	cmd.Flags().BoolVarP(&echo, "echo", "e", false, "echo the password while typing")
	cmd.Flags().BoolVarP(&force, "force", "f", false, "overwrite without prompting")
	return cmd
}

// runInsert reads a new entry and stores it.
func (a *App) runInsert(_ context.Context, name string, multiline, echo, force bool) error {
	s, err := a.requireStore()
	if err != nil {
		return err
	}
	if err := a.Guard().CheckWrite(name); err != nil {
		return err
	}
	if !force && s.Exists(name) {
		ok, err := a.confirm(fmt.Sprintf("An entry already exists for %s. Overwrite it?", name))
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
	}

	var content string
	switch {
	case multiline:
		fmt.Fprintf(a.Out, "Enter contents of %s and press Ctrl+D when finished:\n\n", name)
		data, err := io.ReadAll(a.In)
		if err != nil {
			return err
		}
		content = string(data)
	case echo:
		line, err := a.readLine(fmt.Sprintf("Enter password for %s: ", name))
		if err != nil {
			return err
		}
		content = line + "\n"
	default:
		line, err := a.readPasswordTwice(name)
		if err != nil {
			return err
		}
		content = line + "\n"
	}
	return s.Set(name, secret.Parse([]byte(content)))
}

// readPasswordTwice prompts for a password without echo and requires the two
// entries to match, as pass does.
func (a *App) readPasswordTwice(name string) (string, error) {
	first, err := a.readSecret(fmt.Sprintf("Enter password for %s: ", name))
	if err != nil {
		return "", err
	}
	second, err := a.readSecret(fmt.Sprintf("Retype password for %s: ", name))
	if err != nil {
		return "", err
	}
	if first != second {
		return "", errors.New("Error: the entered passwords do not match.") //nolint:revive,staticcheck // pass's exact wording.
	}
	return first, nil
}

// readSecret reads one line without echoing it. Secrets are never taken from
// argv, so a terminal or a pipe are the only accepted sources.
func (a *App) readSecret(prompt string) (string, error) {
	if f, ok := a.In.(interface{ Fd() uintptr }); ok && term.IsTerminal(int(f.Fd())) {
		fmt.Fprint(a.Err, prompt)
		defer fmt.Fprintln(a.Err)
		b, err := term.ReadPassword(int(f.Fd()))
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	return a.readLine(prompt)
}

// readLine reads one line of input, echoing the prompt.
func (a *App) readLine(prompt string) (string, error) {
	fmt.Fprint(a.Err, prompt)
	r := bufio.NewReader(a.In)
	line, err := r.ReadString('\n')
	if err != nil && (err != io.EOF || line == "") { //nolint:errorlint // io.EOF is returned verbatim.
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// confirm asks a yes/no question, defaulting to no.
func (a *App) confirm(question string) (bool, error) {
	answer, err := a.readLine(question + " [y/N] ")
	if err != nil {
		return false, err
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes", nil
}
