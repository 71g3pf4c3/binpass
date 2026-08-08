// Package importer reads secrets from foreign password managers and converts
// them into entries suitable for a pass-format store.
//
// The core abstraction is the Importer interface: each supported format
// implements Name (for display), Detect (content-based auto-detection), and
// Import (streaming conversion). A Registry holds all known importers and
// resolves the right one from an input file.
//
// Entry is the intermediate representation: it carries the richer structure of
// foreign formats (title, username, URL, group, TOTP, attachments) and is
// later mapped onto a store path and a pass-format secret by the export step.
package importer

import (
	"io"
	"iter"
)

// Entry is a single secret extracted from a foreign format, before it has been
// mapped to a store path and a pass-format secret.
//
// An importer populates whichever fields its source provides; the export step
// ignores empty fields. Password is the only truly required field — even an
// empty password is valid, because the user may intend to edit the entry later.
type Entry struct {
	// Title is the entry name as reported by the source. It is used as the
	// basis for the store path after normalisation.
	Title string

	// Path overrides Title as the store path. When set, the export step uses
	// it directly instead of deriving a path from Title + Group.
	Path string

	// Group is the folder or category the entry belongs to in the source
	// manager (e.g. "Finance/Banks"). It is joined with Title to form the
	// store path when Path is empty.
	Group string

	// Password is the primary secret.
	Password string

	// Username is the login name, written as a "username:" field.
	Username string

	// URL is the associated web address, written as a "url:" field.
	URL string

	// Notes is free-form text appended after structured fields.
	Notes string

	// TOTPURI is an otpauth:// URI, if the source carries a TOTP secret.
	// Importers that find TOTP secrets in other representations (e.g. a
	// separate secret field) must convert them to an otpauth:// URI.
	TOTPURI string

	// Fields are additional "key: value" pairs not covered by the structured
	// fields above.
	Fields []Field

	// Attachments are binary blobs from the source (e.g. KDBX attachments).
	// They are stored as "name.b64" entries with base64-encoded content,
	// following gopass convention (§1 of ARCHITECTURE.md).
	Attachments []Attachment
}

// Field is a key-value pair that becomes a "key: value" line in the secret.
type Field struct {
	// Name is the field label.
	Name string
	// Value is the field content.
	Value string
}

// Attachment is a binary blob from a foreign format, stored as a separate
// base64-encoded entry in the store.
type Attachment struct {
	// Name is the filename of the attachment.
	Name string
	// Data is the raw binary content.
	Data []byte
}

// Importer reads a foreign format and yields entries as a stream.
type Importer interface {
	// Name returns the human-readable name of the source format (e.g.
	// "Bitwarden", "KeePass").
	Name() string

	// Detect reports whether r contains this format. The caller must ensure
	// that r is positioned at the start; the implementation must not consume
	// more bytes than necessary for detection. For binary formats (KDBX), the
	// caller should re-open the file for Import.
	Detect(r io.Reader) bool

	// Import reads r and yields entries. The iterator stops when the reader is
	// exhausted or an error makes further progress impossible. A non-nil error
	// on the value channel means the entry may be partially usable; the caller
	// decides whether to keep it. A non-nil error as the final yield means the
	// import aborted.
	Import(r io.Reader) iter.Seq2[*Entry, error]
}

// Import is a convenience that reads all entries from an importer, stopping at
// the first error that is not attached to an entry.
func ImportAll(imp Importer, r io.Reader) ([]*Entry, error) {
	var entries []*Entry
	for e, err := range imp.Import(r) {
		if err != nil {
			if e != nil {
				// Entry-level error: keep the partial entry but note the
				// problem.
				entries = append(entries, e)
			}
			// Stream-level error: stop.
			return entries, err
		}
		entries = append(entries, e)
	}
	return entries, nil
}
