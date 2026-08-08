// Package tomb hides the entire password store when it is not in use: no file
// names, no directory structure, no metadata visible at rest. Three backends
// implement different trade-offs between security and portability.
//
// Coffin (the default) packs the store into a single age-encrypted archive that
// works everywhere. LUKS (Linux) uses a dm-crypt container for stronger
// guarantees. Sparsebundle (macOS) uses an encrypted APFS image.
//
// The auto-close watcher (timer, screen lock, suspend) is critical: an open
// tomb exposes plaintext, and the value of the feature depends on that window
// being as short as practical.
package tomb

import (
	"errors"
	"fmt"
	"runtime"
	"time"
)

// Backend names the container type.
type Backend string

// Supported backends.
const (
	// BackendCoffin is the cross-platform default: a single age-encrypted tar
	// archive. Works without root, works on every OS.
	BackendCoffin Backend = "coffin"
	// BackendLUKS is a dm-crypt container managed via cryptsetup. Linux only,
	// requires root or polkit. Maximum protection: plaintext exists only in
	// the kernel dm-crypt mapping.
	BackendLUKS Backend = "luks"
	// BackendSparseBundle is an encrypted APFS sparse bundle via hdiutil.
	// macOS only.
	BackendSparseBundle Backend = "sparsebundle"
)

// Sentinel errors.
var (
	// ErrNotInitialised reports that no tomb exists for this store.
	ErrNotInitialised = errors.New("tomb: not initialised")
	// ErrAlreadyOpen reports that the tomb is already open.
	ErrAlreadyOpen = errors.New("tomb: already open")
	// ErrNotOpen reports that the tomb is not open.
	ErrNotOpen = errors.New("tomb: not open")
	// ErrUnsupported reports that the backend is not available on this OS.
	ErrUnsupported = errors.New("tomb: backend not supported on this OS")
	// ErrNotImplemented reports that the backend is defined but not yet built.
	ErrNotImplemented = errors.New("tomb: backend not yet implemented")
	// ErrNeedRoot reports that the backend requires elevated privileges.
	ErrNeedRoot = errors.New("tomb: this backend requires root or polkit")
	// ErrShredWarning is appended to close output to warn about SSD limits.
	ErrShredWarning = errors.New("shred on SSD with wear-leveling does not guarantee data destruction")
)

// State records the runtime state of an open tomb. It is persisted to the
// sidecar directory so that binpass doctor can detect an open container after a
// crash.
type State struct {
	// Backend is the container type in use.
	Backend Backend `json:"backend"`
	// StoreDir is the absolute path where the plaintext store is mounted or
	// extracted.
	StoreDir string `json:"store_dir"`
	// CoffinPath is the path to the encrypted archive (coffin backend only).
	CoffinPath string `json:"coffin_path,omitempty"`
	// MountPoint is the dm-crypt or sparse bundle mount (LUKS/sparsebundle).
	MountPoint string `json:"mount_point,omitempty"`
	// MapperName is the dm-crypt mapper name (LUKS only).
	MapperName string `json:"mapper_name,omitempty"`
	// OpenedAt is when the tomb was opened.
	OpenedAt time.Time `json:"opened_at"`
	// Timer is the auto-close duration; zero means no timer.
	Timer time.Duration `json:"timer,omitempty"`
	// PID is the process that opened the tomb, for stale-state detection.
	PID int `json:"pid"`
}

// IsStale reports whether the opening process is no longer running, indicating
// a crash without clean shutdown.
func (s *State) IsStale() bool {
	if s.PID == 0 {
		return false
	}
	return pidIsDead(s.PID)
}

// Tomb is the interface each backend implements. Callers should not construct a
// backend directly; use Open to select the right one.
type Tomb interface {
	// Init creates an encrypted container for the store at dir. If the store
	// already has content, it is packed into the container.
	Init(dir string, rcp []string, size int64) error
	// Open decrypts the container and makes the plaintext available at dir.
	// If timer > 0, the tomb auto-closes after that duration.
	Open(dir string, timer time.Duration) error
	// Close re-encrypts the plaintext back into the container and removes the
	// plaintext. If force is true, skip the dirty check.
	Close(dir string, force bool) error
	// Status reports the current state of the tomb for this store.
	Status(dir string) (State, bool, error)
	// Name returns the backend name for diagnostics.
	Name() Backend
}

// SelectBackend picks the best available backend for the current OS. The caller
// can override with an explicit choice.
func SelectBackend(want Backend) (Tomb, error) {
	switch want {
	case BackendCoffin, "":
		return newCoffin()
	case BackendLUKS:
		if runtime.GOOS != "linux" {
			return nil, fmt.Errorf("%w: LUKS is Linux-only", ErrUnsupported)
		}
		return newLUKS()
	case BackendSparseBundle:
		if runtime.GOOS != "darwin" {
			return nil, fmt.Errorf("%w: sparsebundle is macOS-only", ErrUnsupported)
		}
		return newSparseBundle()
	default:
		return nil, fmt.Errorf("tomb: unknown backend %q", want)
	}
}

// DefaultBackend returns the best backend for the current OS.
func DefaultBackend() Backend {
	switch runtime.GOOS {
	case "linux":
		// Coffin is the default even on Linux because it needs no root.
		// Users who want LUKS opt in explicitly.
		return BackendCoffin
	case "darwin":
		return BackendCoffin
	default:
		return BackendCoffin
	}
}

// coffinFileName is the name of the encrypted archive inside the store
// directory.
const coffinFileName = "store.coffin.age"
