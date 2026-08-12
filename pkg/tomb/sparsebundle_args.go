package tomb

import (
	"fmt"
	"path/filepath"
	"strings"
)

// The parts of the sparse bundle backend that are pure: how hdiutil is
// invoked, and how its failures are explained.
//
// They live outside sparsebundle_darwin.go so that they compile and are
// tested everywhere. A macOS-only file is a file that only gets exercised
// when someone happens to have a Mac, and the arguments are exactly the part
// worth checking — a misplaced flag is the difference between a bundle and a
// prompt that hangs forever.

// classifyHdiutilError turns an exit status into something actionable.
//
// hdiutil reports a wrong passphrase, a busy image and a missing file all as
// exit status 1 with the detail on stderr. Passing that through unread
// leaves the user with "exit status 1" and no idea whether to look for
// another Finder window or a lost key.
func classifyHdiutilError(out []byte, err error) error {
	text := strings.ToLower(string(out))
	switch {
	case strings.Contains(text, "authentication error"),
		strings.Contains(text, "no valid unwrapping"),
		strings.Contains(text, "corrupt"):
		return fmt.Errorf("tomb: the stored passphrase does not open this bundle: %s", firstLine(out))
	case strings.Contains(text, "resource busy"), strings.Contains(text, "resource temporarily unavailable"):
		return fmt.Errorf("tomb: the bundle is in use; close anything reading the store (Finder, Spotlight) and retry: %s",
			firstLine(out))
	case strings.Contains(text, "no such file"):
		return fmt.Errorf("tomb: %w: %s", ErrNotInitialised, firstLine(out))
	}
	if len(out) == 0 {
		return fmt.Errorf("tomb: hdiutil: %w", err)
	}
	return fmt.Errorf("tomb: hdiutil: %w: %s", err, firstLine(out))
}

// bundlePath returns the path of the sparse bundle inside a store.
func bundlePath(dir string) string { return filepath.Join(dir, bundleName) }

// bundleKeyPath returns the path of the encrypted passphrase.
func bundleKeyPath(dir string) string { return filepath.Join(dir, bundleKeyName) }

// createArgs builds the hdiutil invocation that creates the bundle.
//
// -stdinpass is what keeps the passphrase off the command line: an argument
// would be visible in ps to every process on the machine.
func createArgs(image string, megabytes int64) []string {
	return []string{
		"create",
		"-type", "SPARSEBUNDLE",
		"-fs", "APFS",
		"-encryption", "AES-256",
		"-stdinpass",
		"-size", fmt.Sprintf("%dm", megabytes),
		"-volname", "binpass",
		image,
	}
}

// attachArgs builds the hdiutil invocation that mounts the bundle.
func attachArgs(image, mountpoint string) []string {
	return []string{
		"attach", image,
		"-stdinpass",
		"-mountpoint", mountpoint,
		// Keeping it out of Finder and Spotlight is not cosmetic: an indexer
		// walking the mount would copy entry names into a database outside
		// the tomb, which is the metadata the tomb exists to hide.
		"-nobrowse",
		"-noidme",
	}
}

// detachArgs builds the hdiutil invocation that unmounts the bundle.
func detachArgs(mountpoint string, force bool) []string {
	args := []string{"detach", mountpoint}
	if force {
		args = append(args, "-force")
	}
	return args
}
