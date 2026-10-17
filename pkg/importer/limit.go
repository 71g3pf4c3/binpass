package importer

import (
	"errors"
	"fmt"
	"io"
)

// ErrTooLarge reports an import file that exceeds the size importers accept.
var ErrTooLarge = errors.New("importer: input too large")

// maxImportBytes bounds what an import reads into memory.
//
// An export of a whole password manager is megabytes, so the bound is far
// above any honest file; what it stops is an oversized or compressed-bomb
// "export" a user was talked into importing taking the process down with it.
// It is a variable rather than a constant only so that tests can shrink it
// instead of generating hundreds of megabytes.
var maxImportBytes int64 = 256 << 20

// limitReader wraps r so that reading more than maxImportBytes fails.
//
// A plain io.LimitReader would report EOF instead, and every decoder here
// reads an oversized file as a truncated one: a silently half-imported store
// is worse than a refused import.
func limitReader(r io.Reader) io.Reader {
	return &cappedReader{r: r, max: maxImportBytes}
}

// cappedReader fails once the total it has passed on exceeds max.
type cappedReader struct {
	// r is the underlying stream.
	r io.Reader
	// max is the largest total this reader will deliver.
	max int64
	// n is how much has been read so far.
	n int64
}

// Read implements io.Reader.
func (c *cappedReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	if c.n > c.max {
		return n, fmt.Errorf("%w: input exceeds %d bytes", ErrTooLarge, c.max)
	}
	return n, err
}
