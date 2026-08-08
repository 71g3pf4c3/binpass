package importer

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"iter"
	"strings"
)

// BitwardenImporter reads CSV exports from the Bitwarden password manager.
//
// Bitwarden CSV columns vary between versions. Known column names are mapped
// by csvHeaderIndex so that the code works regardless of column order.
type BitwardenImporter struct{}

// Name returns the format name.
func (BitwardenImporter) Name() string { return "Bitwarden" }

// Detect reports whether r looks like a Bitwarden CSV export.
func (BitwardenImporter) Detect(r io.Reader) bool {
	data, _ := io.ReadAll(io.LimitReader(r, 4096))
	line := firstNonEmptyLine(data)
	// Bitwarden exports start with "folder,favorite,type,name,..." or
	// "group,favorite,type,name,...".
	return strings.Contains(line, "folder,") || strings.Contains(line, "group,") && strings.Contains(line, "favorite,")
}

// Import reads entries from a Bitwarden CSV.
func (BitwardenImporter) Import(r io.Reader) iter.Seq2[*Entry, error] {
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
				Title:    csvField(row, idx, "name"),
				Group:    csvField(row, idx, "folder"),
				Username: csvField(row, idx, "login_username"),
				Password: csvField(row, idx, "login_password"),
				URL:      csvField(row, idx, "login_uri"),
				Notes:    csvField(row, idx, "notes"),
			}

			// Bitwarden TOTP is in login_totp.
			if totp := csvField(row, idx, "login_totp"); totp != "" {
				e.TOTPURI = normalizeTOTP(totp)
			}

			// Skip entries with type "note" that have no meaningful content.
			if e.Title == "" && e.Password == "" && e.Notes == "" {
				continue
			}

			// Bitwarden uses "(null)" as a placeholder for empty URIs.
			if e.URL == "(null)" {
				e.URL = ""
			}

			if !yield(e, nil) {
				return
			}
		}
	}
}

// firstNonEmptyLine returns the first line in data that is not blank.
func firstNonEmptyLine(data []byte) string {
	r := csv.NewReader(bytes.NewReader(data))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	for {
		record, err := r.Read()
		if err != nil {
			return ""
		}
		line := strings.Join(record, ",")
		if strings.TrimSpace(line) != "" {
			return line
		}
	}
}

// normalizeTOTP converts various TOTP representations to an otpauth:// URI.
// Bitwarden exports TOTP secrets as base32 strings, which need wrapping into
// an otpauth:// URI.
func normalizeTOTP(secret string) string {
	// Already an otpauth URI.
	if strings.HasPrefix(strings.ToLower(secret), "otpauth://") {
		return secret
	}
	// Raw base32 secret: wrap into a standard URI.
	return fmt.Sprintf("otpauth://totp/Imported:?secret=%s&issuer=Imported", secret)
}
