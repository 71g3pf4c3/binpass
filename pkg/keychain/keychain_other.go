//go:build !darwin

package keychain

import "errors"

// ErrUnsupported reports that the Keychain is macOS-only.
//
// Windows has its own Credential Manager and Linux has the Secret Service,
// which binpass serves directly; neither is reachable through this package.
var ErrUnsupported = errors.New("keychain: the macOS Keychain is only available on macOS")

// Keychain is unavailable on this platform.
type Keychain struct{}

// Runner executes an external command with optional stdin.
type Runner func(name string, stdin []byte, args ...string) ([]byte, error)

// New is not available on this platform.
func New() (*Keychain, error) { return nil, ErrUnsupported }

// List is not available on this platform.
func (k *Keychain) List() ([]Item, error) { return nil, ErrUnsupported }

// Get is not available on this platform.
func (k *Keychain) Get(string, string) (Item, error) { return Item{}, ErrUnsupported }

// Set is not available on this platform.
func (k *Keychain) Set(Item) error { return ErrUnsupported }

// Delete is not available on this platform.
func (k *Keychain) Delete(string, string) error { return ErrUnsupported }
