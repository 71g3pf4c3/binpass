//go:build !linux

package tomb

import (
	"fmt"
	"time"
)

// LUKS is not available on non-Linux platforms.
type LUKS struct{}

// newLUKS always returns an error on non-Linux.
func newLUKS() (*LUKS, error) {
	return nil, fmt.Errorf("tomb: %w: LUKS is Linux-only", ErrUnsupported)
}

// Name returns BackendLUKS.
func (LUKS) Name() Backend { return BackendLUKS }

// Init is not available.
func (LUKS) Init(string, []string, int64) error { return ErrUnsupported }

// Open is not available.
func (LUKS) Open(string, time.Duration) error { return ErrUnsupported }

// Close is not available.
func (LUKS) Close(string, bool) error { return ErrUnsupported }

// Status is not available.
func (LUKS) Status(string) (State, bool, error) { return State{}, false, ErrUnsupported }
