package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/71g3pf4c3/binpass/pkg/crypto"
	"github.com/71g3pf4c3/binpass/pkg/importer"
	"github.com/71g3pf4c3/binpass/pkg/secret"
	"github.com/71g3pf4c3/binpass/pkg/store"
	"github.com/spf13/cobra"
)

// newImportCmd builds `binpass import`.
func newImportCmd(app *App) *cobra.Command {
	var (
		format   string
		dryRun   bool
		force    bool
		encoding string
	)
	cmd := &cobra.Command{
		Use:   "import [--format=FORMAT] [--dry-run] [--force] FILE",
		Short: "Import passwords from another password manager",
		Long: `Import passwords from a foreign password manager into the store.

Auto-detects the format from the file content when --format is not given.
Use --dry-run to preview what will be imported without writing anything.

For the pass and gopass formats, FILE is the source store directory; entries
are decrypted with the keys of the current user and re-encrypted for this
store. Entries that cannot be decrypted are imported with their ciphertext
as an attachment.

Supported formats: Bitwarden, 1Password, LastPass, Chrome, Firefox, Enpass,
KeePass (KDBX), pass, gopass.`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return app.runImport(args[0], format, dryRun, force, encoding)
		},
	}
	cmd.Flags().StringVar(&format, "format", "", "source format (auto-detected if empty)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be imported without writing")
	cmd.Flags().BoolVarP(&force, "force", "f", false, "overwrite existing entries")
	cmd.Flags().StringVar(&encoding, "encoding", "", "character encoding (e.g. windows-1251); auto-detected if empty")
	return cmd
}

// newExportCmd builds `binpass export`.
func newExportCmd(app *App) *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "export [--format=FORMAT] [PATH]",
		Short: "Export the password store to another format",
		Long: `Export the password store to a CSV file.

WARNING: exported files contain decrypted passwords in plain text. Delete
them after use and never commit them to version control.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return app.runExport(format, args)
		},
	}
	cmd.Flags().StringVar(&format, "format", "csv", "export format (csv)")
	return cmd
}

// runImport performs the import operation.
func (a *App) runImport(path, format string, dryRun, force bool, encoding string) error {
	s, err := a.requireStore()
	if err != nil {
		return err
	}

	registry := importer.NewRegistry()

	var imp importer.Importer
	if format != "" {
		imp = registry.ByName(format)
		if imp == nil {
			return fmt.Errorf("import: unknown format %q (run 'binpass import --help' for a list)", format)
		}
	} else {
		// Detect format from file content.
		f, err := os.Open(path) //nolint:gosec // user-provided path.
		if err != nil {
			return fmt.Errorf("import: %w", err)
		}
		imp, _, err = registry.DetectReader(f)
		_ = f.Close()
		if err != nil {
			return fmt.Errorf("import: detecting format: %w", err)
		}
		if imp == nil {
			return fmt.Errorf("import: could not detect format of %q (use --format to specify)", path)
		}
	}

	// For pass and gopass, the argument is a source store directory rather
	// than a file: bind it, plus a store to decrypt that directory through.
	// These importers read by path, so there is no input stream to prepare —
	// reading a directory as a file would fail before they even run.
	dirBased := false
	switch pi := imp.(type) {
	case *importer.PassImporter:
		a.bindPassImporter(pi, path)
		dirBased = true
	case *importer.GopassImporter:
		a.bindPassImporter(&pi.PassImporter, path)
		dirBased = true
	}

	var f io.Reader
	if !dirBased {
		// Re-open the file for the importer (DetectReader consumed the reader).
		// An explicit --encoding transcodes here, before any importer sees the
		// bytes: importers work in UTF-8, and the store requires it.
		raw, err := os.ReadFile(path) //nolint:gosec // user-provided path.
		if err != nil {
			return fmt.Errorf("import: %w", err)
		}
		raw, err = importer.Decode(raw, encoding)
		if err != nil {
			return fmt.Errorf("import: decoding as %q: %w", encoding, err)
		}
		f = bytes.NewReader(raw)
	}

	// For KeePass, we need a password from the terminal. Use readSecret
	// (no echo) to avoid displaying the database password.
	if kdbx, ok := imp.(*importer.KeePassImporter); ok {
		pw, err := a.readSecret("Enter KeePass database password: ")
		if err != nil {
			return fmt.Errorf("import: reading password: %w", err)
		}
		kdbx.Password = pw
	}

	entries, err := importer.ImportAll(imp, f)
	if err != nil {
		return fmt.Errorf("import: %w", err)
	}

	// Entries that could not be decrypted arrive as ciphertext attachments;
	// the importer does not abort on them, so summarise here where the
	// operator is guaranteed to look.
	if n := countCiphertextFallbacks(entries); n > 0 {
		fmt.Fprintf(a.Err, "pass import: %d entries could not be decrypted; they were imported with their ciphertext as attachments\n", n)
	}

	if dryRun {
		plans := importer.Plan(s, entries)
		a.printf("%s", importer.FormatPlan(plans))
		return nil
	}

	written, errs := importer.WriteEntries(s, entries, force)
	for _, w := range written {
		a.printf("Imported %s\n", w)
	}
	for _, e := range errs {
		fmt.Fprintln(a.Err, e)
	}

	if len(errs) > 0 {
		return fmt.Errorf("import: %d entries had errors", len(errs))
	}
	return nil
}

// runExport performs the export operation.
func (a *App) runExport(format string, args []string) error {
	s, err := a.requireStore()
	if err != nil {
		return err
	}

	names, err := s.List("")
	if err != nil {
		return err
	}

	// Export as CSV to stdout or to the specified file.
	w := a.Out
	if len(args) == 1 {
		f, err := os.Create(args[0]) //nolint:gosec // user-provided path.
		if err != nil {
			return fmt.Errorf("export: %w", err)
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	fmt.Fprintln(w, "path,username,password,url,otp,notes")
	for _, name := range names {
		sec, err := s.Get(name)
		if err != nil {
			fmt.Fprintf(a.Err, "skip %s: %v\n", name, err)
			continue
		}
		username, _ := sec.Field("username")
		url, _ := sec.Field("url")
		otp, _ := sec.OTP()
		notes := csvEscape(freeFormNotes(sec))

		fmt.Fprintf(w, "%s,%s,%s,%s,%s,%s\n",
			csvEscape(name),
			csvEscape(username),
			csvEscape(sec.Password()),
			csvEscape(url),
			csvEscape(otp),
			notes,
		)
	}
	return nil
}

// bindPassImporter points a pass/gopass importer at a source store directory
// and gives it a store to decrypt through, so imported entries are re-encrypted
// for the destination's recipients instead of arriving as ciphertext
// attachments.
func (a *App) bindPassImporter(pi *importer.PassImporter, dir string) {
	pi.Dir = dir
	gpg := crypto.NewGPG(dir, a.Cfg.GPGBinary, a.Cfg.GPGOpts)
	ageBackend := crypto.NewAge(dir, a.identities)
	// The default backend only matters for writes, and a source store is
	// never written; gpg keeps the lookup order pass-compatible anyway.
	src, err := store.New(store.Options{
		Dir:      dir,
		Backends: []crypto.Crypto{gpg, ageBackend},
		Default:  gpg,
	})
	if err == nil {
		pi.Source = src
	}
}

// countCiphertextFallbacks reports how many imported entries carry their
// ciphertext as an attachment, i.e. could not be decrypted at import time.
func countCiphertextFallbacks(entries []*importer.Entry) int {
	n := 0
	for _, e := range entries {
		for _, att := range e.Attachments {
			if strings.HasPrefix(att.Name, "_ciphertext") {
				n++
				break
			}
		}
	}
	return n
}

// csvEscape returns s quoted for CSV if it contains commas, quotes or newlines.
func csvEscape(s string) string {
	if s == "" {
		return ""
	}
	needsQuote := false
	for _, r := range s {
		if r == ',' || r == '"' || r == '\n' || r == '\r' {
			needsQuote = true
			break
		}
	}
	if !needsQuote {
		return s
	}
	// strings.Builder handles multi-byte runes correctly.
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for _, r := range s {
		if r == '"' {
			b.WriteByte('"')
		}
		b.WriteRune(r)
	}
	b.WriteByte('"')
	return b.String()
}

// exportedFieldLines are the body line shapes the CSV carries in their own
// columns. Everything else in the body is note material and must survive the
// export: dropping it would not deduplicate, it would lose data.
var exportedFieldLines = []string{"username:", "url:"}

// freeFormNotes extracts the note lines of a secret: the body without the
// lines the export already carries in dedicated columns. With the whole
// body in notes, every re-import duplicated username, url and otp — a
// roundtrip that grew on each pass.
func freeFormNotes(sec *secret.Secret) string {
	var notes []string
	for _, line := range sec.Lines()[1:] { // the first line is the password
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "otpauth://") {
			continue
		}
		dup := false
		for _, p := range exportedFieldLines {
			if strings.HasPrefix(line, p) {
				dup = true
				break
			}
		}
		if !dup {
			notes = append(notes, line)
		}
	}
	return strings.Join(notes, "\n")
}
