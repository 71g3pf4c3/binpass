package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/71g3pf4c3/binpass/pkg/importer"
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

	// Re-open the file for the importer (DetectReader consumed the reader).
	f, err := os.Open(path) //nolint:gosec // user-provided path.
	if err != nil {
		return fmt.Errorf("import: %w", err)
	}
	defer func() { _ = f.Close() }()

	// For KeePass, we need a password from the terminal. Use readSecret
	// (no echo) to avoid displaying the database password.
	if kdbx, ok := imp.(*importer.KeePassImporter); ok {
		pw, err := a.readSecret("Enter KeePass database password: ")
		if err != nil {
			return fmt.Errorf("import: reading password: %w", err)
		}
		kdbx.Password = pw
	}

	// For pass importer, set the source directory.
	if passImp, ok := imp.(*importer.PassImporter); ok {
		passImp.Dir = path
	}

	entries, err := importer.ImportAll(imp, f)
	if err != nil {
		return fmt.Errorf("import: %w", err)
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
		notes := csvEscape(sec.Body())

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
