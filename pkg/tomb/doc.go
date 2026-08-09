// Package tomb hides the entire password store when it is not in use: no file
// names, no directory structure, no metadata visible at rest. Three backends
// implement different trade-offs between security and portability.
//
// # Backends
//
// Coffin (the default) packs the store into a single age-encrypted tar archive
// (store.coffin.age). Open decrypts to a private directory (tmpfs on Linux,
// 0700 + shred elsewhere). Close re-encrypts and shreds the plaintext.
// Works everywhere, no root required.
//
// LUKS (Linux only) uses a dm-crypt container managed via the external
// cryptsetup binary. Plaintext exists only in the kernel dm-crypt mapping,
// never on disk. Requires root or polkit. Not yet implemented.
//
// Sparsebundle (macOS only) uses an encrypted APFS sparse bundle via hdiutil.
// Not yet implemented.
//
// # Lifecycle
//
// A tomb follows a strict state machine:
//
//	Uninitialised ──Init──▶ Closed ──Open──▶ Open ──Close──▶ Closed
//	                                      ▲         │
//	                                      └─────────┘
//	                                   (auto-close: timer, screen lock, suspend)
//
// Init creates the encrypted container from the existing store directory. The
// plaintext is left in place; the user should close or remove it manually.
//
// Open decrypts the container and writes state to a sidecar directory
// ($XDG_DATA_HOME/binpass/<name>-tomb.state). The state file records the PID,
// backend, timer, and timestamp so that crash recovery can detect stale state.
//
// Close re-encrypts the current plaintext into the container (atomic tmp+rename),
// shreds the plaintext directory, and removes the state file.
//
// # Auto-close
//
// The Watcher monitors OS events and fires a callback when the tomb should
// auto-close:
//   - Timer: close after a configurable duration.
//   - Screen lock (Linux): D-Bus signals from GNOME/KDE screensaver.
//   - Suspend (Linux): D-Bus PrepareForSleep from logind.
//
// On non-Linux, only the timer is available. The watcher is started by the
// CLI's "tomb open" command and runs in background goroutines.
//
// # State file
//
// The state file is stored outside the store directory so that sync (git,
// cloud) never picks it up. It lives in $XDG_DATA_HOME/binpass/ (or
// $BINPASS_DATA_DIR) as <basename>-tomb.state, keyed by the store
// directory's base name. The state includes:
//   - Backend type (coffin, luks, sparsebundle)
//   - Store directory absolute path
//   - Process PID (for stale-state detection)
//   - OpenedAt timestamp
//   - Timer duration
//
// If the opening process has crashed, IsStale() returns true (by checking
// whether the PID still exists via syscall.Kill). The next Open call detects
// this and cleans up the stale state.
//
// # Security considerations
//
// Plaintext exposure: the coffin backend writes decrypted files to a directory
// on disk (tmpfs on Linux, 0700 directory elsewhere). The plaintext is exposed
// for the duration of the session. Auto-close mitigates but does not eliminate
// this. The LUKS backend (when implemented) will provide stronger guarantees.
//
// Shred limitations: overwriteRandom writes crypto/rand bytes over each file
// before removal. On SSDs with wear-leveling, this does not guarantee that the
// original data is physically overwritten. On tmpfs (Linux), the data lives
// only in RAM and is destroyed on unmount or reboot.
//
// mlock: on Linux, mlockDir attempts to mmap and mlock files under 64KB in
// the store directory. This prevents them from being swapped to disk. Failures
// are silently ignored (mlock is advisory hardening).
//
// Archive integrity: the coffin archive is age-encrypted. Age provides
// authenticated encryption; tampering with the ciphertext causes decryption to
// fail. However, a replacement coffin encrypted under the same recipient will
// decrypt successfully. Trust in the coffin's contents depends on the
// integrity of the storage medium (local disk, git, cloud sync).
//
// Dotfile preservation: Close preserves dotfiles (.age-recipients, .gpg-id,
// .git) so that the next Open can find recipients and git can work. This means
// an attacker with write access to the store directory could plant a dotfile
// that survives close. In the single-user local threat model, anyone with write
// access to the directory already has access to the plaintext during the open
// session.
package tomb
