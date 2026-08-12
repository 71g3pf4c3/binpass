package tomb

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/71g3pf4c3/binpass/pkg/crypto"
)

// maxContainerKeyLen bounds a key or passphrase read back from disk.
const maxContainerKeyLen = 4096

// Helpers shared by the tomb backends that drive external tools: LUKS through
// cryptsetup on Linux, and the sparse bundle through hdiutil on macOS.
//
// Both need the same three things, and neither can be tested without them: a
// command runner that a test can replace, a way to move the store's existing
// entries into a fresh container, and a container file that reports its full
// size without occupying it.

// execRunner runs a command for real, feeding it stdin when given.
//
// The key file is passed this way rather than as a path or an argument:
// a temporary file would put the decrypted key on disk, and an argument would
// publish it in /proc to every process on the machine.
func execRunner(name string, stdin []byte, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...) //nolint:gosec // callers pass fixed binaries and arguments built here.
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	return cmd.CombinedOutput()
}

// firstLine returns the first non-empty line of command output, which is
// where cryptsetup puts the actual reason.
func firstLine(out []byte) string {
	for _, line := range strings.Split(string(out), "\n") {
		if s := strings.TrimSpace(line); s != "" {
			return s
		}
	}
	return ""
}

// createSparseFile creates a file that reports size bytes but occupies only
// the blocks actually written.
func createSparseFile(path string, size int64) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // a path binpass derived, not user input.
	if err != nil {
		return fmt.Errorf("tomb: create container: %w", err)
	}
	defer func() { _ = f.Close() }()

	if err := f.Truncate(size); err != nil {
		return fmt.Errorf("tomb: size container: %w", err)
	}
	return nil
}

// copyTree copies the contents of src into dst, skipping the named entries.
func copyTree(src, dst string, skip ...string) error {
	skipSet := make(map[string]bool, len(skip))
	for _, s := range skip {
		skipSet[s] = true
	}

	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if skipSet[rel] {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		target := filepath.Join(dst, rel)
		// A symlink in the store could otherwise walk the copy out of the
		// container and write wherever it points.
		if !isWithin(dst, target) {
			return fmt.Errorf("tomb: refusing to copy %q outside the container", rel)
		}
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if !d.Type().IsRegular() {
			// Sockets and devices have no business in a password store,
			// and copying them into the container would be a way to smuggle
			// something odd past the next reader.
			return nil
		}
		data, err := os.ReadFile(path) //nolint:gosec // walking the store binpass was pointed at.
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o600) //nolint:gosec // target checked against the container root above.
	})
}

// zero overwrites a key in memory once it is no longer needed. It is not a
// guarantee — Go may have copied the slice — but leaving the key sitting in a
// live buffer for the rest of the process is worse.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// commandRunner executes an external command with optional stdin, returning
// its combined output. It exists so that argument construction and error
// handling can be tested without root, a loop device, or cryptsetup.
type commandRunner func(name string, stdin []byte, args ...string) ([]byte, error)

// writeEncryptedKey encrypts the container key to the store's recipients.
func writeEncryptedKey(path string, key []byte, rcp []string) error {
	recipients, err := crypto.ParseAgeRecipients(toRecipients(rcp))
	if err != nil {
		return fmt.Errorf("tomb: container key: %w", err)
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // a path binpass derived, not user input.
	if err != nil {
		return fmt.Errorf("tomb: create key file: %w", err)
	}
	defer func() { _ = f.Close() }()

	w, err := age.Encrypt(f, recipients...)
	if err != nil {
		return fmt.Errorf("tomb: encrypt container key: %w", err)
	}
	if _, err := w.Write(key); err != nil {
		_ = w.Close()
		return fmt.Errorf("tomb: encrypt container key: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("tomb: encrypt container key: %w", err)
	}
	return f.Sync()
}

// readEncryptedKey decrypts a container key or passphrase.
func readEncryptedKey(path string, ids []age.Identity) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // path is constructed from dir + constant.
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("tomb: container key file is missing: %s", path)
		}
		return nil, fmt.Errorf("tomb: open key file: %w", err)
	}
	defer func() { _ = f.Close() }()

	r, err := age.Decrypt(f, ids...)
	if err != nil {
		return nil, fmt.Errorf("tomb: decrypt container key: %w", err)
	}
	// Bounded: the file is ours, but it arrives through a sync that another
	// machine wrote, and an unbounded read of an attacker-supplied file is
	// how a password manager becomes an out-of-memory crash.
	key, err := io.ReadAll(io.LimitReader(r, maxContainerKeyLen))
	if err != nil {
		return nil, fmt.Errorf("tomb: read container key: %w", err)
	}
	if len(key) == 0 {
		return nil, errors.New("tomb: container key file is empty")
	}
	return key, nil
}

// randomPassphrase returns a passphrase for a container that asks for one
// rather than for a key file.
//
// It is printable because hdiutil reads it as text on stdin; base64 of 32
// random bytes carries 256 bits either way.
func randomPassphrase() ([]byte, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("tomb: generating a passphrase: %w", err)
	}
	out := make([]byte, base64.RawStdEncoding.EncodedLen(len(raw)))
	base64.RawStdEncoding.Encode(out, raw)
	zero(raw)
	return out, nil
}
