package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/71g3pf4c3/binpass/pkg/secret"
	"github.com/spf13/cobra"
)

// newGrepCmd builds `binpass grep`.
func newGrepCmd(app *App) *cobra.Command {
	var ignoreCase bool
	cmd := &cobra.Command{
		Use:   "grep [GREPOPTIONS] search-string",
		Short: "Search decrypted passwords for a string",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return app.runGrep(cmd.Context(), args[0], ignoreCase)
		},
	}
	cmd.Flags().BoolVarP(&ignoreCase, "ignore-case", "i", false, "match case-insensitively")
	return cmd
}

// runGrep decrypts every entry and prints the lines that match.
func (a *App) runGrep(_ context.Context, pattern string, ignoreCase bool) error {
	s, err := a.requireStore()
	if err != nil {
		return err
	}
	expr := pattern
	if ignoreCase {
		expr = "(?i)" + expr
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return err
	}

	matches, err := s.Grep("", func(line string) bool { return re.MatchString(line) })
	if err != nil {
		return err
	}
	// grep decrypts the whole store, so a restricted plugin sees only the
	// entries it was granted. Filtering rather than refusing keeps grep
	// useful to a plugin scoped to one subtree.
	for _, m := range matches {
		if err := a.Guard().CheckDecrypt(m.Name); err != nil {
			continue
		}
		dir, base := filepath.Split(m.Name)
		fmt.Fprintf(a.Out, "\033[94m%s\033[1m%s\033[0m:\n", dir, base)
		for _, line := range m.Lines {
			fmt.Fprintln(a.Out, re.ReplaceAllStringFunc(line, func(s string) string {
				return "\033[01;31m" + s + "\033[0m"
			}))
		}
	}
	return nil
}

// newEditCmd builds `binpass edit`.
func newEditCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "edit pass-name",
		Short: "Edit a password using $EDITOR",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return app.runEdit(cmd.Context(), args[0])
		},
	}
}

// runEdit decrypts an entry into a private temporary file, runs $EDITOR, and
// stores the result. The plaintext never leaves a 0600 file that is removed
// on every exit path.
func (a *App) runEdit(ctx context.Context, name string) error {
	s, err := a.requireStore()
	if err != nil {
		return err
	}
	// Editing both reveals the plaintext and replaces it, so it needs both.
	if err := a.Guard().CheckDecrypt(name); err != nil {
		return err
	}
	if err := a.Guard().CheckWrite(name); err != nil {
		return err
	}
	var original []byte
	if sec, err := s.Get(name); err == nil {
		original = sec.Bytes()
	}

	dir := secureTempDir()
	f, err := os.CreateTemp(dir, "binpass-*.txt")
	if err != nil {
		return err
	}
	path := f.Name()
	defer func() {
		_ = f.Close()
		_ = shred(path)
	}()

	if err := f.Chmod(0o600); err != nil {
		return err
	}
	if _, err := f.Write(original); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	if err := runEditor(ctx, path); err != nil {
		return err
	}
	edited, err := os.ReadFile(path) //nolint:gosec // our own temporary file.
	if err != nil {
		return err
	}
	if string(edited) == string(original) {
		fmt.Fprintf(a.Err, "Password unchanged.\n")
		return nil
	}
	return s.Set(name, secret.Parse(edited))
}

// runEditor launches $EDITOR on path, attached to the terminal.
func runEditor(ctx context.Context, path string) error {
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = os.Getenv("VISUAL")
	}
	if editor == "" {
		editor = "vi"
	}
	// $EDITOR conventionally may carry arguments ("code --wait"), so it is
	// split rather than executed as a single filename.
	parts := strings.Fields(editor)
	args := make([]string, 0, len(parts))
	args = append(args, parts[1:]...)
	args = append(args, path)

	cmd := exec.CommandContext(ctx, parts[0], args...) //nolint:gosec // $EDITOR is the user's own choice.
	// The editor needs the real terminal, not the command's captured streams.
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

// newGitCmd builds `binpass git`.
func newGitCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:                "git git-command-args...",
		Short:              "Run a git command inside the password store",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return app.runGit(cmd.Context(), args)
		},
	}
}

// runGit executes git inside the store directory.
func (a *App) runGit(ctx context.Context, args []string) error {
	cmd := exec.CommandContext(ctx, "git", args...) //nolint:gosec // the user's own git arguments.
	cmd.Dir = a.Cfg.Dir
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, a.Out, a.Err
	// pass clears these so that a git invocation cannot be redirected at
	// another repository by the surrounding environment.
	cmd.Env = append(os.Environ(),
		"GIT_DIR=", "GIT_WORK_TREE=", "GIT_NAMESPACE=", "GIT_INDEX_FILE=",
		"GIT_CEILING_DIRECTORIES="+filepath.Dir(a.Cfg.Dir),
	)
	return cmd.Run()
}

// newVersionCmd builds `binpass version`.
func newVersionCmd(app *App, version, commit, buildDate string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			app.printf("binpass %s\n", version)
			app.printf("commit: %s\n", commit)
			app.printf("built:  %s\n", buildDate)
			return nil
		},
	}
}
