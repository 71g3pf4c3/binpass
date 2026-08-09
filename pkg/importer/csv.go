package importer

import (
	"bytes"
	"encoding/base64"
	"encoding/csv"
	"io"
	"unicode/utf8"

	"golang.org/x/text/encoding/htmlindex"
	"golang.org/x/text/transform"
)

// csvReadAll reads a CSV file from r, handling:
//   - UTF-8 BOM (EF BB BF) and UTF-16 BOM (FF FE / FE FF)
//   - Non-UTF-8 encodings (detected heuristically, or specified explicitly)
//   - Multiline fields (quoted values containing newlines)
//
// If encoding is empty, it attempts UTF-8 first and falls back to
// sniffing the encoding from the BOM or from byte patterns.
func csvReadAll(r io.Reader, encoding string) ([][]string, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	raw = stripBOM(raw)

	if encoding != "" {
		raw, err = decodeBytes(raw, encoding)
		if err != nil {
			return nil, err
		}
	} else if !utf8.Valid(raw) {
		// Heuristic: if it's not valid UTF-8, try CP1251 (common for Russian
		// LastPass exports), then ISO-8859-1 as a last resort.
		for _, enc := range []string{"windows-1251", "iso-8859-1"} {
			decoded, err := decodeBytes(raw, enc)
			if err != nil {
				continue
			}
			raw = decoded
			break
		}
	}

	reader := csv.NewReader(bytes.NewReader(raw))
	// Allow variable field counts — different export versions have different
	// columns.
	reader.FieldsPerRecord = -1
	// Relax strict quoting rules — some exporters don't quote properly.
	reader.LazyQuotes = true
	return reader.ReadAll()
}

// stripBOM removes a UTF-8 or UTF-16 BOM from the start of data.
func stripBOM(data []byte) []byte {
	if bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF}) {
		return data[3:]
	}
	// UTF-16 LE BOM
	if bytes.HasPrefix(data, []byte{0xFF, 0xFE}) {
		return data[2:]
	}
	// UTF-16 BE BOM
	if bytes.HasPrefix(data, []byte{0xFE, 0xFF}) {
		return data[2:]
	}
	return data
}

// decodeBytes re-encodes data from the named encoding to UTF-8.
func decodeBytes(data []byte, encName string) ([]byte, error) {
	enc, err := htmlindex.Get(encName)
	if err != nil {
		return nil, err
	}
	decoded, err := io.ReadAll(transform.NewReader(bytes.NewReader(data), enc.NewDecoder()))
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

// csvHeaderIndex builds a map from column names (lowercased) to their indices
// in the header row. This allows each importer to look up columns by name
// rather than position, which varies between export versions.
func csvHeaderIndex(header []string) map[string]int {
	m := make(map[string]int, len(header))
	for i, h := range header {
		m[toLowerCase(h)] = i
	}
	return m
}

// toLowerCase is a simple ASCII lower-case that avoids importing strings
// for this leaf function.
func toLowerCase(s string) string {
	var b bytes.Buffer
	b.Grow(len(s))
	for _, r := range s {
		if r >= 'A' && r <= 'Z' {
			r += 'a' - 'A'
		}
		b.WriteRune(r)
	}
	return b.String()
}

// csvField extracts the value at column name from row, using idx for lookup.
// Returns empty string if the column is missing or the value is empty.
func csvField(row []string, idx map[string]int, name string) string {
	i, ok := idx[name]
	if !ok || i >= len(row) {
		return ""
	}
	return row[i]
}

// b64Encode encodes data as base64 with line breaks, matching the format used
// by gopass for binary entries.
func b64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}
