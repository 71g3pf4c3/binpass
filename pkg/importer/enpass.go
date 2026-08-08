package importer

import (
	"io"
	"iter"
	"strings"
)

// EnpassImporter reads CSV exports from Enpass.
//
// Enpass exports vary by version. Common column names include "Title",
// "User Name", "Password", "Web Site", "Remarks", "Group", and custom fields
// as additional columns.
type EnpassImporter struct{}

// Name returns the format name.
func (EnpassImporter) Name() string { return "Enpass" }

// Detect reports whether r looks like an Enpass CSV export.
func (EnpassImporter) Detect(r io.Reader) bool {
	data, _ := io.ReadAll(io.LimitReader(r, 4096))
	line := firstNonEmptyLine(data)
	lower := toLowerCase(line)
	// Enpass includes "Recycle Bin" or "Category" columns in some versions.
	return strings.Contains(lower, "title") &&
		strings.Contains(lower, "password") &&
		(strings.Contains(lower, "remarks") || strings.Contains(lower, "category"))
}

// Import reads entries from an Enpass CSV.
func (EnpassImporter) Import(r io.Reader) iter.Seq2[*Entry, error] {
	return func(yield func(*Entry, error) bool) {
		rows, err := csvReadAll(r, "")
		if err != nil {
			yield(nil, err)
			return
		}
		if len(rows) == 0 {
			return
		}
		idx := csvHeaderIndex(rows[0])
		for _, row := range rows[1:] {
			e := &Entry{
				Title:    csvField(row, idx, "title"),
				Username: csvField(row, idx, "user name"),
				Password: csvField(row, idx, "password"),
				URL:      csvField(row, idx, "web site"),
				Notes:    csvField(row, idx, "remarks"),
				Group:    csvField(row, idx, "category"),
			}

			// Enpass may have a "group" column in addition to "category".
			if e.Group == "" {
				e.Group = csvField(row, idx, "group")
			}

			// Skip entries in the recycle bin.
			if strings.EqualFold(e.Group, "recycle bin") {
				continue
			}

			if e.Title == "" && e.Password == "" && e.Notes == "" {
				continue
			}

			if !yield(e, nil) {
				return
			}
		}
	}
}
