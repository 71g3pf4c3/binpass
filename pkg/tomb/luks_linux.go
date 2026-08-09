//go:build linux

package tomb

import (
	"fmt"
	"os/exec"
	"time"
)

// LUKS manages a dm-crypt container via the external cryptsetup binary. The
// plaintext exists only in the kernel's dm-crypt mapping and never touches
// disk. The key file is encrypted with age/GPG, so hardware tokens work.
//
// Requires root or a polkit policy that grants the user access to cryptsetup.
// The key file is decrypted by shelling out to the configured backend rather
// than in-process, so no identity function is held here.
type LUKS struct{}

// newLUKS returns a LUKS backend. It checks that cryptsetup is available.
func newLUKS() (*LUKS, error) {
	if _, err := exec.LookPath("cryptsetup"); err != nil {
		return nil, fmt.Errorf("tomb: cryptsetup not found on PATH: %w", err)
	}
	return &LUKS{}, nil
}

// Name returns BackendLUKS.
func (l *LUKS) Name() Backend { return BackendLUKS }

// Init creates a LUKS container and an age-encrypted key file.
func (l *LUKS) Init(dir string, rcp []string, size int64) error {
	return ErrNotImplemented
}

// Open decrypts the key file, calls cryptsetup luksOpen, and mounts the
// container at dir.
func (l *LUKS) Open(dir string, timer time.Duration) error {
	return ErrNotImplemented
}

// Close unmounts the container and calls cryptsetup luksClose.
func (l *LUKS) Close(dir string, force bool) error {
	return ErrNotImplemented
}

// Status reports the current state.
func (l *LUKS) Status(dir string) (State, bool, error) {
	st, err := loadState(dir)
	if err != nil {
		return State{}, false, err
	}
	return *st, !st.IsStale(), nil
}
