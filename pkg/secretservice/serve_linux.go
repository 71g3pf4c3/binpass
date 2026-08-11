//go:build linux

package secretservice

import (
	"context"
	"fmt"
	"os"

	"github.com/godbus/dbus/v5"
)

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

// Serve runs the provider until the context is cancelled.
func Serve(ctx context.Context, opts ServeOptions) error {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return fmt.Errorf("secretservice: connecting to the session bus: %w", err)
	}
	defer func() { _ = conn.Close() }()

	store := NewStore(opts.Store, opts.IndexSeed)

	// The index is what makes lookup possible without decrypting every
	// item, so a store synchronised from another machine is indexed here
	// before the first client asks for anything.
	if _, err := store.Reindex(); err != nil {
		return err
	}

	var notify *os.File
	if opts.Notify != nil {
		notify = opts.Notify
	}
	engine := NewPolicyEngine(opts.Policy, func(sender string) (string, error) {
		return callerExe(conn, sender)
	}, notify)

	svc := NewService(conn, store, engine)
	if err := svc.Export(opts.Takeover); err != nil {
		return err
	}

	<-ctx.Done()
	return nil
}

// callerExe resolves a bus sender to the executable behind it.
func callerExe(conn *dbus.Conn, sender string) (string, error) {
	var pid uint32
	err := conn.BusObject().Call("org.freedesktop.DBus.GetConnectionUnixProcessID", 0, sender).Store(&pid)
	if err != nil {
		return "", err
	}
	return processExe(int(pid))
}

// Owner returns who currently owns the Secret Service bus name.
//
// This is what `binpass ss doctor` reports: the usual reason the provider
// will not start is that gnome-keyring is already there, and naming it turns
// a refusal into an instruction.
func Owner() (string, bool, error) {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return "", false, fmt.Errorf("secretservice: connecting to the session bus: %w", err)
	}
	defer func() { _ = conn.Close() }()

	var has bool
	if err := conn.BusObject().Call("org.freedesktop.DBus.NameHasOwner", 0, BusName).Store(&has); err != nil {
		return "", false, err
	}
	if !has {
		return "", false, nil
	}

	var owner string
	if err := conn.BusObject().Call("org.freedesktop.DBus.GetNameOwner", 0, BusName).Store(&owner); err != nil {
		return "", true, err
	}
	var pid uint32
	if err := conn.BusObject().Call("org.freedesktop.DBus.GetConnectionUnixProcessID", 0, owner).Store(&pid); err != nil {
		return owner, true, nil
	}
	exe, err := processExe(int(pid))
	if err != nil {
		return fmt.Sprintf("pid %d", pid), true, nil
	}
	return fmt.Sprintf("%s (pid %d)", exe, pid), true, nil
}
