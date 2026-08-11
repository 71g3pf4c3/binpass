package plugin

import (
	"errors"
	"fmt"
)

// ErrDenied reports an operation a plugin's capabilities do not permit.
var ErrDenied = errors.New("plugin: denied by capabilities")

// Guard enforces capabilities on store operations.
//
// It exists because a manifest that is displayed but not enforced is
// decoration. When binpass runs on a plugin's behalf, every store operation
// passes through here first.
type Guard struct {
	// Name is the plugin the guard acts for, used in error messages.
	Name string
	// Caps are the capabilities that were granted.
	Caps Capabilities
	// Active reports whether a plugin is in fact driving this process.
	Active bool
}

// NewGuard returns the guard for the current process.
func NewGuard(name string, caps Capabilities, active bool) *Guard {
	return &Guard{Name: name, Caps: caps, Active: active}
}

// Unrestricted returns a guard that permits everything, for a binpass the
// user invoked directly.
func Unrestricted() *Guard { return &Guard{} }

// CanRead reports whether the plugin may see that an entry exists.
func (g *Guard) CanRead(name string) bool {
	if !g.Active {
		return true
	}
	return MatchAny(g.Caps.ReadPaths, name)
}

// CanWrite reports whether the plugin may create or modify an entry.
func (g *Guard) CanWrite(name string) bool {
	if !g.Active {
		return true
	}
	return MatchAny(g.Caps.WritePaths, name)
}

// CanDecrypt reports whether the plugin may see plaintext for an entry.
//
// Reading a path and decrypting it are separate grants, so a plugin can be
// allowed to inventory the store without ever being shown a password.
func (g *Guard) CanDecrypt(name string) bool {
	if !g.Active {
		return true
	}
	return g.Caps.Decrypt && MatchAny(g.Caps.ReadPaths, name)
}

// CheckRead returns an error unless the entry may be read.
func (g *Guard) CheckRead(name string) error {
	if g.CanRead(name) {
		return nil
	}
	return g.deny("read", name, g.Caps.ReadPaths)
}

// CheckWrite returns an error unless the entry may be written.
func (g *Guard) CheckWrite(name string) error {
	if g.CanWrite(name) {
		return nil
	}
	return g.deny("write", name, g.Caps.WritePaths)
}

// CheckDecrypt returns an error unless the entry's plaintext may be read.
func (g *Guard) CheckDecrypt(name string) error {
	if !g.Active {
		return nil
	}
	if !g.Caps.Decrypt {
		return fmt.Errorf("%w: plugin %q did not request decrypt, so it cannot read secrets",
			ErrDenied, g.Name)
	}
	if !MatchAny(g.Caps.ReadPaths, name) {
		return g.deny("decrypt", name, g.Caps.ReadPaths)
	}
	return nil
}

// CheckExec returns an error unless the plugin may run an external binary.
func (g *Guard) CheckExec(bin string) error {
	if !g.Active {
		return nil
	}
	if !coversHosts(g.Caps.Exec, []string{bin}) {
		return fmt.Errorf("%w: plugin %q may not run %q; its manifest allows %v",
			ErrDenied, g.Name, bin, g.Caps.Exec)
	}
	return nil
}

// CheckNetwork returns an error unless the plugin may reach a host.
func (g *Guard) CheckNetwork(host string) error {
	if !g.Active {
		return nil
	}
	if !coversHosts(g.Caps.Network, []string{host}) {
		return fmt.Errorf("%w: plugin %q may not reach %q; its manifest allows %v",
			ErrDenied, g.Name, host, g.Caps.Network)
	}
	return nil
}

// FilterReadable returns the entries the plugin may know about.
//
// Listing is filtered rather than refused so that a plugin scoped to one
// subtree sees a coherent store containing exactly its subtree, instead of an
// error it would have to work around.
func (g *Guard) FilterReadable(names []string) []string {
	if !g.Active {
		return names
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		if MatchAny(g.Caps.ReadPaths, n) {
			out = append(out, n)
		}
	}
	return out
}

// deny builds a denial that names what was refused and what was allowed,
// since a plugin author's first question is always which pattern to add.
func (g *Guard) deny(action, name string, allowed []string) error {
	if len(allowed) == 0 {
		return fmt.Errorf("%w: plugin %q may not %s %q; its manifest requests no %s access",
			ErrDenied, g.Name, action, name, action)
	}
	return fmt.Errorf("%w: plugin %q may not %s %q; its manifest allows %v",
		ErrDenied, g.Name, action, name, allowed)
}
