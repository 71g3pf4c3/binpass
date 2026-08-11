package importer

import (
	"io"
	"iter"
	"strings"
)

// LastPassImporter reads CSV exports from LastPass.
//
// LastPass exports use columns: url,username,password,extra,name,grouping,fav
// The "extra" field contains notes. "grouping" maps to the store group.
// LastPass may encode the CSV in the system's default encoding rather than
// UTF-8, which is why csvReadAll handles encoding detection.
type LastPassImporter struct{}

// Name returns the format name.
func (LastPassImporter) Name() string { return "LastPass" }

// Detect reports whether r looks like a LastPass CSV export.
func (LastPassImporter) Detect(r io.Reader) bool {
	data, _ := io.ReadAll(io.LimitReader(r, 4096))
	line := firstNonEmptyLine(data)
	lower := toLowerCase(line)
	return strings.Contains(lower, "url,username,password,extra,name,grouping") ||
		(strings.Contains(lower, "url") && strings.Contains(lower, "grouping") && strings.Contains(lower, "extra"))
}

// Import reads entries from a LastPass CSV.
func (LastPassImporter) Import(r io.Reader) iter.Seq2[*Entry, error] {
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
			name := csvField(row, idx, "name")
			// LastPass uses "http://sn" as a placeholder for secure notes
			// without a URL.
			url := csvField(row, idx, "url")
			if url == "http://sn" {
				url = ""
			}

			e := &Entry{
				Title:    name,
				Group:    csvField(row, idx, "grouping"),
				Username: csvField(row, idx, "username"),
				Password: csvField(row, idx, "password"),
				URL:      url,
				Notes:    csvField(row, idx, "extra"),
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
