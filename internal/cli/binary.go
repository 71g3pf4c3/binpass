package cli

import (
	"fmt"
	"os"

	"github.com/71g3pf4c3/binpass/pkg/binary"
	"github.com/spf13/cobra"
)

// newBinaryCmd builds `binpass binary` with subcommands: cat, sum, copy, move.
func newBinaryCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "binary",
		Short: "Manage binary secrets in the store",
		Long: `Manage binary secrets stored as base64-encoded entries.

Binary entries follow the gopass convention: their name ends in ".b64"
and the encrypted content is the base64 representation of the original
binary data. This allows images, keys, certificates, and other binary
files to be versioned and synced alongside text secrets.`,
		Aliases: []string{"bin"},
	}

	cmd.AddCommand(
		newBinaryCatCmd(app),
		newBinarySumCmd(app),
		newBinaryCopyCmd(app),
		newBinaryMoveCmd(app),
	)
	return cmd
}

// newBinaryCatCmd builds `binpass binary cat`.
func newBinaryCatCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "cat pass-name",
		Short: "Decode and output a binary entry to stdout",
		Long: `Decode and output the binary content of a .b64 entry to stdout.

The entry name must end in ".b64". The base64-encoded content is decoded
and written to standard output, suitable for piping to a file:

    binpass binary cat photo.b64 > photo.jpg`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return app.runBinaryCat(args[0])
		},
	}
}

// newBinarySumCmd builds `binpass binary sum`.
func newBinarySumCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "sum pass-name",
		Short: "Print the SHA-256 checksum of a binary entry",
		Long: `Print the SHA-256 checksum of the decoded binary content.

The entry name must end in ".b64". The checksum is computed on the
decoded (original) binary data, not on the base64 representation.

    binpass binary sum photo.b64`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return app.runBinarySum(args[0])
		},
	}
}

// newBinaryCopyCmd builds `binpass binary copy`.
func newBinaryCopyCmd(app *App) *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "copy pass-name file",
		Short: "Encode a file into the store as a binary entry",
		Long: `Encode a file as base64 and store it under the given name.

The entry name must end in ".b64". The source file is not modified.

    binpass binary copy photo.b64 photo.jpg`,
		Aliases: []string{"cp"},
		Args:    cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			return app.runBinaryCopy(args[0], args[1], force)
		},
	}
	cmd.Flags().BoolVarP(&force, "force", "f", false, "overwrite without prompting")
	return cmd
}

// newBinaryMoveCmd builds `binpass binary move`.
func newBinaryMoveCmd(app *App) *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "move pass-name file",
		Short: "Encode a file into the store and delete the original",
		Long: `Encode a file as base64, store it under the given name, then delete the original file.

The entry name must end in ".b64".

    binpass binary move photo.b64 photo.jpg

This is equivalent to ` + "`binpass binary copy`" + ` followed by removing the source file.`,
		Aliases: []string{"mv"},
		Args:    cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			return app.runBinaryMove(args[0], args[1], force)
		},
	}
	cmd.Flags().BoolVarP(&force, "force", "f", false, "overwrite without prompting")
	return cmd
}

// runBinaryCat decodes a .b64 entry to the output stream.
func (a *App) runBinaryCat(name string) error {
	s, err := a.requireStore()
	if err != nil {
		return err
	}
	return binary.Cat(s, name, a.Out)
}

// runBinarySum prints the SHA-256 of a .b64 entry's decoded content.
func (a *App) runBinarySum(name string) error {
	s, err := a.requireStore()
	if err != nil {
		return err
	}
	sum, err := binary.Sum(s, name)
	if err != nil {
		return err
	}
	fmt.Fprintln(a.Out, sum)
	return nil
}

// runBinaryCopy encodes a file as base64 and stores it under name.
func (a *App) runBinaryCopy(name, path string, force bool) error {
	s, err := a.requireStore()
	if err != nil {
		return err
	}
	proceed, err := a.overwriteEntry(s, name, force)
	if err != nil || !proceed {
		return err
	}
	f, err := os.Open(path) //nolint:gosec // user-supplied path is intentional.
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return binary.Store(s, name, f)
}

// runBinaryMove stores a file under name and removes the original.
func (a *App) runBinaryMove(name, path string, force bool) error {
	s, err := a.requireStore()
	if err != nil {
		return err
	}
	proceed, err := a.overwriteEntry(s, name, force)
	if err != nil || !proceed {
		return err
	}
	f, err := os.Open(path) //nolint:gosec // user-supplied path is intentional.
	if err != nil {
		return err
	}
	// Closed explicitly below and again on every error path; the
	// second close is harmless and the first is required because
	// Windows refuses to remove an open file.
	defer func() { _ = f.Close() }()

	if err := binary.Store(s, name, f); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Remove(path)
}

// overwriteEntry asks whether an existing entry may be replaced, unless
// force was given. It reports whether the operation may proceed; a declined
// prompt is not an error — the command ends quietly, exactly as it did
// before the question was asked, leaving the entry untouched.
func (a *App) overwriteEntry(s interface{ Exists(string) bool }, name string, force bool) (bool, error) {
	if force || !s.Exists(name) {
		return true, nil
	}
	return a.confirm(fmt.Sprintf("An entry already exists for %s. Overwrite it?", name))
}
