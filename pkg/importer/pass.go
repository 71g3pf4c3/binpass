package importer

import (
	"fmt"
	"io"
	"iter"
	"os"
	"path/filepath"
	"strings"
)

// PassImporter reads entries from an existing pass or gopass store on disk.
// It does not decrypt; it copies the ciphertext, which the export step can
// then re-encrypt for the target store.
//
// Because pass stores use the same format as binpass, this importer is also
// the basis for "binpass import pass /path/to/other/store".
type PassImporter struct {
	// Dir is the path to the source pass store. If empty, the importer
	// reports an error at import time.
	Dir string
}

// Name returns the format name.
func (PassImporter) Name() string { return "pass" }

// Detect reports whether the reader looks like a pass store. A pass store is
// identified by its directory structure (a tree of .gpg or .age files with a
// .gpg-id or .age-recipients file), not by a single file's content, so Detect
// always returns false when called on a stream. Use PassImporter with Dir set
// instead.
func (PassImporter) Detect(_ io.Reader) bool { return false }

// Import walks the source store directory and yields entries. It reads the
// ciphertext from each entry but does not decrypt it; the Password field is
// left empty and the raw ciphertext is carried in a special field so that the
// export step can re-encrypt without needing the source store's keys.
func (p *PassImporter) Import(_ io.Reader) iter.Seq2[*Entry, error] {
	return func(yield func(*Entry, error) bool) {
		if p.Dir == "" {
			yield(nil, fmt.Errorf("importer: pass importer requires a source directory"))
			return
		}

		err := filepath.Walk(p.Dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			name := filepath.Base(path)
			// Skip metadata and dotfiles.
			if strings.HasPrefix(name, ".") {
				return nil
			}

			// Determine the entry name relative to the store root.
			rel, err := filepath.Rel(p.Dir, path)
			if err != nil {
				return err
			}

			// Strip the encryption extension.
			entryName := rel
			if ext := filepath.Ext(rel); ext == ".gpg" || ext == ".age" {
				entryName = rel[:len(rel)-len(ext)]
			} else {
				// Not an encrypted entry; skip.
				return nil
			}

			// Use forward slashes for the store path.
			entryName = filepath.ToSlash(entryName)

			// Read the raw ciphertext (will be re-encrypted by export step).
			data, err := os.ReadFile(path) //nolint:gosec // path is from a user-provided directory.
			if err != nil {
				// Report but don't abort: one unreadable entry shouldn't stop
				// the whole import.
				yield(&Entry{Title: entryName}, fmt.Errorf("pass: read %s: %w", rel, err))
				return nil
			}

			ext := filepath.Ext(rel)
			e := &Entry{
				Path: entryName,
				Fields: []Field{
					{Name: "source-format", Value: "pass"},
					{Name: "source-ext", Value: ext},
				},
				// Carry raw ciphertext for the export step.
				Attachments: []Attachment{{
					Name: "_ciphertext" + ext,
					Data: data,
				}},
			}

			if !yield(e, nil) {
				return fmt.Errorf("importer: iteration stopped")
			}
			return nil
		})
		if err != nil {
			yield(nil, err)
		}
	}
}
