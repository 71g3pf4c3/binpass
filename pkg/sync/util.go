package sync

import (
	"bytes"
	"io"
	"sort"
)

// sortStrings sorts s in place ascending.
func sortStrings(s []string) { sort.Strings(s) }

// bytesReader returns an io.Reader over b.
func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }
