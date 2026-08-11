//go:build !linux

package secretservice

import (
	"context"
	"errors"
	"os"
)

// ErrUnsupported reports that the Secret Service provider is Linux-only.
//
// The API is a freedesktop D-Bus interface: macOS and Windows have their own
// keystores, which binpass integrates with rather than replaces (§6.5).
var ErrUnsupported = errors.New("secretservice: org.freedesktop.secrets is Linux-only")

// ServeOptions configures the provider.
type ServeOptions struct {
	// Store is the password store items live in.
	Store PassStore
	// IndexSeed derives the attribute index key.
	IndexSeed []byte
	// Policy is the access policy.
	Policy Config
	// Takeover says what to do when the bus name is taken.
	Takeover Takeover
	// Notify receives access notifications.
	Notify *os.File
}

// Serve is not available on this platform.
func Serve(context.Context, ServeOptions) error { return ErrUnsupported }

// Owner is not available on this platform.
func Owner() (string, bool, error) { return "", false, ErrUnsupported }
