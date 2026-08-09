package importer

import (
	"io"
	"sort"
)

// Registry holds known importers and resolves the right one for an input.
type Registry struct {
	importers []Importer
}

// NewRegistry returns a registry with the standard set of importers.
func NewRegistry() *Registry {
	r := &Registry{}
	r.Register(
		&BitwardenImporter{},
		&OnePasswordImporter{},
		&LastPassImporter{},
		&ChromeImporter{},
		&FirefoxImporter{},
		&EnpassImporter{},
		&KeePassImporter{},
		&PassImporter{},
	)
	return r
}

// Register adds one or more importers to the registry.
func (r *Registry) Register(imps ...Importer) {
	r.importers = append(r.importers, imps...)
}

// Importers returns all registered importers sorted by name.
func (r *Registry) Importers() []Importer {
	out := make([]Importer, len(r.importers))
	copy(out, r.importers)
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name() < out[j].Name()
	})
	return out
}

// Detect reads the beginning of r and returns the first importer that
// recognises the content. The caller should re-open the file for Import,
// because Detect consumes an unspecified number of bytes.
//
// If no importer matches, it returns nil.
func (r *Registry) Detect(peek []byte) Importer {
	for _, imp := range r.importers {
		if imp.Detect(bytesReader(peek)) {
			return imp
		}
	}
	return nil
}

// DetectReader is like Detect but reads from an io.Reader. It buffers up to
// peekSize bytes for detection.
func (r *Registry) DetectReader(rd io.Reader) (Importer, []byte, error) {
	peek := make([]byte, 0, peekSize)
	buf := make([]byte, peekSize)
	for len(peek) < peekSize {
		n, err := rd.Read(buf)
		peek = append(peek, buf[:n]...)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, peek, err
		}
	}
	return r.Detect(peek), peek, nil
}

// peekSize is the number of bytes read for format detection. All supported
// formats have identifiable content in the first 4 KiB.
const peekSize = 4096

// bytesReader returns a Reader that reads from b.
func bytesReader(b []byte) io.Reader {
	return &byteReader{data: b}
}

type byteReader struct {
	data []byte
	pos  int
}

func (r *byteReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

// ByName returns the importer with the given name, or nil.
func (r *Registry) ByName(name string) Importer {
	for _, imp := range r.importers {
		if stringsEqualFold(imp.Name(), name) {
			return imp
		}
	}
	return nil
}

// stringsEqualFold reports whether s and t are equal, ignoring case.
func stringsEqualFold(s, t string) bool {
	if len(s) != len(t) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if lower(s[i]) != lower(t[i]) {
			return false
		}
	}
	return true
}

func lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}
