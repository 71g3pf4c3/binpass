package importer

import (
	"io"
	"iter"
	"strings"
)

// FirefoxImporter reads CSV exports from Firefox Lockwise / Firefox Password
// Manager.
//
// Firefox exports use: url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged
// Only url, username, and password carry secret data; the rest are metadata.
type FirefoxImporter struct{}

// Name returns the format name.
func (FirefoxImporter) Name() string { return "Firefox" }

// Detect reports whether r looks like a Firefox CSV export.
func (FirefoxImporter) Detect(r io.Reader) bool {
	data, _ := io.ReadAll(io.LimitReader(r, 4096))
	line := firstNonEmptyLine(data)
	lower := toLowerCase(line)
	return strings.Contains(lower, "url,username,password") &&
		(strings.Contains(lower, "httprealm") || strings.Contains(lower, "formactionorigin") || strings.Contains(lower, "guid"))
}

// Import reads entries from a Firefox CSV.
func (FirefoxImporter) Import(r io.Reader) iter.Seq2[*Entry, error] {
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
			url := csvField(row, idx, "url")
			title := extractDomain(url)
			if title == "" {
				title = csvField(row, idx, "httprealm")
			}

			e := &Entry{
				Title:    title,
				Username: csvField(row, idx, "username"),
				Password: csvField(row, idx, "password"),
				URL:      url,
			}

			if e.Title == "" && e.Password == "" {
				continue
			}

			if !yield(e, nil) {
				return
			}
		}
	}
}

// extractDomain returns the hostname from a URL, used as a fallback title
// when Firefox does not provide one.
func extractDomain(rawURL string) string {
	u := rawURL
	// Strip common prefixes.
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	u = strings.TrimPrefix(u, "ftp://")
	// Take up to the first slash or port.
	if i := strings.IndexAny(u, "/:"); i > 0 {
		u = u[:i]
	}
	return u
}
