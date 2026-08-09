// Package importer reads secrets from foreign password managers (Bitwarden,
// 1Password, LastPass, Chrome, Firefox, Enpass, KeePass, pass, gopass) and
// converts them into entries suitable for a pass-format store.
//
// The core abstraction is the Importer interface: each format implements Name
// (for display), Detect (content-based auto-detection), and Import (streaming
// conversion). A Registry holds all known importers and resolves the right one
// from an input file.
//
// Entry is the intermediate representation: it carries the richer structure of
// foreign formats (title, username, URL, group, TOTP, attachments) and is
// mapped onto a store path and a pass-format secret by the export step.
//
// Usage:
//
// Import a file with auto-detection:
//
//	registry := importer.NewRegistry()
//	imp, _, _ := registry.DetectReader(file)
//	entries, _ := importer.ImportAll(imp, file)
//	importer.WriteEntries(store, entries, false)
//
// Plan without writing (dry-run):
//
//	plans := importer.Plan(store, entries)
//	fmt.Println(importer.FormatPlan(plans))
package importer
