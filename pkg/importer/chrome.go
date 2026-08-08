package importer

import (
	"io"
	"iter"
	"strings"
)

// ChromeImporter reads CSV exports from Google Chrome's password manager.
//
// Chrome exports use: name,url,username,password,note
// The first line may contain a explanatory prefix that must be skipped.
type ChromeImporter struct{}

// Name returns the format name.
func (ChromeImporter) Name() string { return "Chrome" }

// Detect reports whether r looks like a Chrome CSV export.
func (ChromeImporter) Detect(r io.Reader) bool {
	data, _ := io.ReadAll(io.LimitReader(r, 4096))
	// Chrome on some locales uses the header in the local language, but the
	// presence of "name,url,username,password" in English is the most reliable
	// signal. Some versions prefix with explanatory text.
	lines := splitLines(data)
	for _, line := range lines {
		lower := toLowerCase(strings.TrimSpace(line))
		if lower == "" {
			continue
		}
		return strings.Contains(lower, "name") &&
			strings.Contains(lower, "url") &&
			strings.Contains(lower, "username") &&
			strings.Contains(lower, "password")
	}
	return false
}

// Import reads entries from a Chrome CSV.
func (ChromeImporter) Import(r io.Reader) iter.Seq2[*Entry, error] {
	return func(yield func(*Entry, error) bool) {
		rows, err := csvReadAll(r, "")
		if err != nil {
			yield(nil, err)
			return
		}
		// Chrome may have a descriptive line before the header. Skip lines
		// that don't look like a header.
		headerIdx := 0
		for i, row := range rows {
			lower := toLowerCase(strings.Join(row, ","))
			if strings.Contains(lower, "name") && strings.Contains(lower, "url") {
				headerIdx = i
				break
			}
		}
		if headerIdx >= len(rows) {
			return
		}
		idx := csvHeaderIndex(rows[headerIdx])
		for _, row := range rows[headerIdx+1:] {
			e := &Entry{
				Title:    csvField(row, idx, "name"),
				Username: csvField(row, idx, "username"),
				Password: csvField(row, idx, "password"),
				URL:      csvField(row, idx, "url"),
				Notes:    csvField(row, idx, "note"),
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

// splitLines splits data into lines without consuming it.
func splitLines(data []byte) []string {
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}
