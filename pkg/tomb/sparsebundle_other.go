//go:build !darwin

package tomb

import (
	"fmt"
	"time"
)

// SparseBundle is not available on non-macOS platforms.
type SparseBundle struct{}

// newSparseBundle always returns an error on non-macOS.
func newSparseBundle() (*SparseBundle, error) {
	return nil, fmt.Errorf("tomb: %w: sparsebundle is macOS-only", ErrUnsupported)
}

// Name returns BackendSparseBundle.
func (SparseBundle) Name() Backend { return BackendSparseBundle }

// Init is not available.
func (SparseBundle) Init(string, []string, int64) error { return ErrUnsupported }

// Open is not available.
func (SparseBundle) Open(string, time.Duration) error { return ErrUnsupported }

// Close is not available.
func (SparseBundle) Close(string, bool) error { return ErrUnsupported }

// Status is not available.
func (SparseBundle) Status(string) (State, bool, error) { return State{}, false, ErrUnsupported }
