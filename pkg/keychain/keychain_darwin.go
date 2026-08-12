//go:build darwin

package keychain

import (
	"bytes"
	"fmt"
	"os/exec"
)

// Keychain is the macOS Keychain, driven through security(1).
type Keychain struct {
	// runner executes security(1); replaced in tests.
	runner Runner
}

// Runner executes an external command with optional stdin. It exists so
// that the logic around security(1) can be tested without a Mac.
type Runner func(name string, stdin []byte, args ...string) ([]byte, error)

// New returns a Keychain, checking that security(1) is available.
func New() (*Keychain, error) {
	if _, err := exec.LookPath("security"); err != nil {
		return nil, fmt.Errorf("keychain: security(1) not found: %w", err)
	}
	return &Keychain{runner: execRunner}, nil
}

// execRunner runs security(1) for real.
func execRunner(name string, stdin []byte, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...) //nolint:gosec // a fixed binary with arguments built in this package.
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	return cmd.CombinedOutput()
}

// run executes security(1) through the configured runner.
func (k *Keychain) run(stdin []byte, args ...string) ([]byte, error) {
	runner := k.runner
	if runner == nil {
		runner = execRunner
	}
	out, err := runner("security", stdin, args...)
	if err != nil {
		return out, classifyError(out, err)
	}
	return out, nil
}

// List returns every generic password in the Keychain, without secrets.
func (k *Keychain) List() ([]Item, error) {
	out, err := k.run(nil, dumpArgs()...)
	if err != nil {
		return nil, err
	}
	return parseDump(out), nil
}

// Get reads one item, including its secret.
//
// This is what prompts the user, one item at a time, which is why the
// listing above does not ask for secrets.
func (k *Keychain) Get(service, account string) (Item, error) {
	out, err := k.run(nil, findArgs(service, account)...)
	if err != nil {
		return Item{}, err
	}
	return Item{
		Service:  service,
		Account:  account,
		Password: string(bytes.TrimRight(out, "\n")),
	}, nil
}

// Set stores an item, replacing any existing one with the same service and
// account.
func (k *Keychain) Set(it Item) error {
	// The password goes in on stdin: as an argument it would be visible in
	// ps to every process on the machine.
	_, err := k.run([]byte(it.Password), addArgs(it)...)
	return err
}

// Delete removes an item.
func (k *Keychain) Delete(service, account string) error {
	_, err := k.run(nil, deleteArgs(service, account)...)
	return err
}
