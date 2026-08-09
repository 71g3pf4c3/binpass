package importer

import (
	"io"
	"iter"
	"strings"
)

// OnePasswordImporter reads CSV exports from 1Password.
//
// 1Password exports vary by vault type. The "Login" export has columns like
// Title, Username, Password, URL, OTP, Notes. The "1Password 8" format uses
// slightly different names.
type OnePasswordImporter struct{}

// Name returns the format name.
func (OnePasswordImporter) Name() string { return "1Password" }

// Detect reports whether r looks like a 1Password CSV export.
func (OnePasswordImporter) Detect(r io.Reader) bool {
	data, _ := io.ReadAll(io.LimitReader(r, 4096))
	line := firstNonEmptyLine(data)
	lower := toLowerCase(line)
	return strings.Contains(lower, "title") &&
		(strings.Contains(lower, "password") || strings.Contains(lower, "otp"))
}

// Import reads entries from a 1Password CSV.
func (OnePasswordImporter) Import(r io.Reader) iter.Seq2[*Entry, error] {
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
				Username: csvField(row, idx, "username"),
				Password: csvField(row, idx, "password"),
				URL:      csvField(row, idx, "url"),
				Notes:    csvField(row, idx, "notes"),
			}

			// 1Password may place the group in "vault" or "category".
			e.Group = csvField(row, idx, "vault")
			if e.Group == "" {
				e.Group = csvField(row, idx, "category")
			}

			// TOTP: 1Password exports the OTP secret in "otp" column, sometimes
			// as an otpauth:// URI, sometimes as a raw secret.
			if totp := csvField(row, idx, "otp"); totp != "" {
				e.TOTPURI = normalizeTOTP(totp)
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
