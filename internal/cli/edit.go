package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
)

// newEditCmd builds the "edit" command.
func newEditCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "edit <name>",
		Short: "Edit a secret in $EDITOR",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			st, err := openStore(cmd)
			if err != nil {
				return err
			}

			var current []byte
			if st.Exists(name) {
				current, err = st.GetRaw(name)
				if err != nil {
					return err
				}
			}

			edited, err := editInEditor(current)
			if err != nil {
				return err
			}
			if err := st.SetRaw(name, edited); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "updated %s\n", name)
			return nil
		},
	}
}

// editInEditor opens content in $EDITOR via a 0600 temp file and returns the
// edited bytes; the temp file is overwritten and removed afterwards.
func editInEditor(content []byte) ([]byte, error) {
	dir := os.TempDir()
	if xrd := os.Getenv("XDG_RUNTIME_DIR"); xrd != "" {
		dir = xrd
	}
	f, err := os.CreateTemp(dir, "binpass-*.txt")
	if err != nil {
		return nil, fmt.Errorf("edit: temp file: %w", err)
	}
	tmp := f.Name()
	defer func() {
		_ = os.WriteFile(tmp, make([]byte, len(content)), 0o600)
		_ = os.Remove(tmp)
	}()
	if err := os.Chmod(tmp, 0o600); err != nil {
		f.Close()
		return nil, err
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		return nil, err
	}
	f.Close()

	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vi"
	}
	c := exec.Command(editor, filepath.Clean(tmp))
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := c.Run(); err != nil {
		return nil, fmt.Errorf("edit: editor: %w", err)
	}
	return os.ReadFile(tmp)
}
