package importer

import (
	"fmt"
	"io"
	"iter"
	"os"
	"path/filepath"
	"strings"

	"github.com/71g3pf4c3/binpass/pkg/store"
)

// PassImporter reads entries from an existing pass or gopass store on disk.
//
// With Source set, entries are decrypted through that store — the same crypto
// backends the destination uses — and carried as ordinary secrets, so the
// export step re-encrypts them for the destination's recipients. Entries that
// cannot be decrypted (no secret key, cancelled pinentry, absent gpg binary)
// fall back to carrying the ciphertext as an attachment, which is what the
// importer has always done for stores whose keys are unavailable.
//
// Because pass stores use the same format as binpass, this importer is also
// the basis for "binpass import pass /path/to/other/store".
type PassImporter struct {
	// Dir is the path to the source pass store. If empty, the importer
	// reports an error at import time.
	Dir string

	// Source is a store bound to Dir through which entries are decrypted.
	// Nil keeps the ciphertext-copying behaviour.
	Source *store.Store
}

// Name returns the format name.
func (PassImporter) Name() string { return "pass" }

// GopassImporter reads a gopass store. gopass shares pass's on-disk layout,
// so the entry discovery and decryption logic is inherited unchanged.
type GopassImporter struct {
	PassImporter
}

// Name returns the format name.
func (GopassImporter) Name() string { return "gopass" }

// Detect reports whether the reader looks like a pass store. A pass store is
// identified by its directory structure (a tree of .gpg or .age files with a
// .gpg-id or .age-recipients file), not by a single file's content, so Detect
// always returns false when called on a stream. Use PassImporter with Dir set
// instead.
func (PassImporter) Detect(_ io.Reader) bool { return false }

// Import walks the source store directory and yields entries. When Source is
// set, each entry is decrypted through it and carried as a pre-rendered
// secret, preserving the source plaintext byte for byte. Entries that fail
// to decrypt, and all entries when Source is nil, are yielded with their raw
// ciphertext as an attachment so a later manual decryption can still recover
// them.
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
			ext := filepath.Ext(rel)
			if ext != ".gpg" && ext != ".age" {
				// Not an encrypted entry; skip.
				return nil
			}
			entryName := filepath.ToSlash(rel[:len(rel)-len(ext)])

			data, err := os.ReadFile(path) //nolint:gosec // path is from a user-provided directory.
			if err != nil {
				// Report but don't abort: one unreadable entry shouldn't stop
				// the whole import.
				yield(&Entry{Title: entryName}, fmt.Errorf("pass: read %s: %w", rel, err))
				return nil
			}

			if p.Source != nil {
				sec, derr := p.Source.Get(entryName)
				if derr == nil {
					e := &Entry{
						Path:     entryName,
						Password: sec.Password(),
						// Carry the decrypted secret verbatim: the
						// structured Entry fields cannot express an
						// arbitrary pass body, and rebuilding one would
						// rewrite the entry instead of transferring it.
						Raw: sec,
					}
					if !yield(e, nil) {
						return errIterationStopped
					}
					return nil
				}
				// Decryption failed: fall back to the ciphertext. No error
				// is yielded because one undecryptable entry must not
				// abort the whole import; the fallback is visible in the
				// entry itself (no password, a _ciphertext attachment) and
				// summarised by the caller.
			}

			if !yield(ciphertextEntry(entryName, ext, data), nil) {
				return errIterationStopped
			}
			return nil
		})
		if err != nil {
			yield(nil, err)
		}
	}
}

// errIterationStopped makes filepath.Walk unwind when the consumer stops
// pulling, so no further files are read and decrypted for nobody.
var errIterationStopped = fmt.Errorf("importer: iteration stopped")

// ciphertextEntry builds the fallback form of an entry: the undecrypted bytes
// travel as an attachment, with the source extension kept so the operator
// knows which tool to point at them.
func ciphertextEntry(name, ext string, data []byte) *Entry {
	return &Entry{
		Path: name,
		Fields: []Field{
			{Name: "source-format", Value: "pass"},
			{Name: "source-ext", Value: ext},
		},
		Attachments: []Attachment{{
			Name: "_ciphertext" + ext,
			Data: data,
		}},
	}
}
