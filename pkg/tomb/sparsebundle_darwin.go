//go:build darwin

package tomb

import (
	"fmt"
	"os/exec"
	"time"
)

// SparseBundle manages an encrypted APFS sparse bundle via hdiutil. By
// protection level it is closer to LUKS, by convenience closer to coffin.
// The key can be stored in Keychain or on a hardware token.
type SparseBundle struct{}

// newSparseBundle returns a SparseBundle backend. It checks that hdiutil is
// available (it always is on macOS).
func newSparseBundle() (*SparseBundle, error) {
	if _, err := exec.LookPath("hdiutil"); err != nil {
		return nil, fmt.Errorf("tomb: hdiutil not found: %w", err)
	}
	return &SparseBundle{}, nil
}

// Name returns BackendSparseBundle.
func (s *SparseBundle) Name() Backend { return BackendSparseBundle }

// Init creates an encrypted sparse bundle.
func (s *SparseBundle) Init(dir string, rcp []string, size int64) error {
	return ErrNotImplemented
}

// Open attaches the sparse bundle.
func (s *SparseBundle) Open(dir string, timer time.Duration) error {
	return ErrNotImplemented
}

// Close detaches the sparse bundle.
func (s *SparseBundle) Close(dir string, force bool) error {
	return ErrNotImplemented
}

// Status reports the current state.
func (s *SparseBundle) Status(dir string) (State, bool, error) {
	st, err := loadState(dir)
	if err != nil {
		return State{}, false, err
	}
	return *st, !st.IsStale(), nil
}
