//go:build !linux

package tomb

// mlockDir is a no-op on non-Linux platforms. Memory locking through mmap is
// either unavailable or requires a different API. The security benefit of
// mlock is marginal on macOS and Windows, where the plaintext directory is not
// on a tmpfs anyway.
func mlockDir(_ string) {}
