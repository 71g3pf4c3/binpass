# pkg/tomb — hide the entire password store at rest

## Overview

`pkg/tomb` implements the "tomb" feature from ARCHITECTURE §7: the entire password
store is hidden when not in use — no file names, no directory structure, no metadata
visible at rest. Three backends provide different trade-offs:

| Backend | OS | Root | Protection level |
|---------|-----|------|-------------------|
| **Coffin** | All | No | Age-encrypted tar archive. Plaintext in tmpfs during session. |
| LUKS | Linux | Yes | dm-crypt container. Plaintext only in kernel mapping. |
| Sparsebundle | macOS | No | Encrypted APFS sparse bundle. |

Coffin is the default everywhere. LUKS and sparsebundle are stubs returning
`ErrNotImplemented`.

## State machine

```
Uninitialised ──Init──▶ Closed ──Open──▶ Open ──Close──▶ Closed
                                  ▲         │
                                  └─────────┘
                               (auto-close: timer, screen lock, suspend)
```

- **Init**: Creates `store.coffin.age` from the current store content. Plaintext
  is **not** removed — Init is additive. The store continues to work normally
  until the user closes it.
- **Open**: Decrypts the coffin into the store directory. Writes a state file
  to the sidecar directory (`$XDG_DATA_HOME/binpass/`). Starts the auto-close
  watcher. Blocks until SIGINT/SIGTERM or auto-close fires.
- **Close**: Re-encrypts the current plaintext into the coffin (atomic tmp+rename),
  shreds the plaintext directory, removes the state file. Preserves dotfiles
  (`.age-recipients`, `.gpg-id`, `.git`).
- **Status**: Reads the state file and reports whether the tomb is open, closed,
  or stale (crash without clean shutdown).

## Files

| File | Purpose |
|------|---------|
| `tomb.go` | Package doc, `Tomb` interface, `State` struct, `Backend` enum, `SelectBackend`, `DefaultBackend`, sentinel errors |
| `doc.go` | Extended package-level documentation |
| `coffin.go` | Coffin backend: Init, Open, Close, Status, packEncrypt, unpackDecrypt, writeTar, readTar, shredDir, overwriteRandom, isWithin |
| `state.go` | State persistence: loadState, saveState, RemoveState, statePath, stateDir |
| `watcher_linux.go` | Auto-close watcher: timer + D-Bus (GNOME/KDE screensaver, logind suspend) |
| `watcher_other.go` | Auto-close watcher: timer only (macOS, Windows) |
| `mlock_linux.go` | `mlockDir`: mmap + Mlock for files < 64KB |
| `mlock_other.go` | `mlockDir`: no-op |
| `pid_unix.go` | `pidIsDead` via `syscall.Kill(pid, 0)` |
| `pid_windows.go` | `pidIsDead`: always returns false (conservative) |
| `luks_linux.go` | LUKS stub: checks cryptsetup on PATH, returns `ErrNotImplemented` |
| `luks_other.go` | LUKS stub: returns `ErrUnsupported` |
| `sparsebundle_darwin.go` | Sparsebundle stub: checks hdiutil, returns `ErrNotImplemented` |
| `sparsebundle_other.go` | Sparsebundle stub: returns `ErrUnsupported` |

## Coffin format

```
store.coffin.age = age.Encrypt(tar(store_dir/))
```

The tar archive contains all non-dotfile, non-coffin entries from the store
directory. Directory permissions are preserved. Symlinks are stored as tar
symlink headers. Dotfiles (`.age-recipients`, `.gpg-id`, `.git/`) are **not**
archived — they persist on disk between close/open cycles.

On Open:
1. `age.Decrypt` with the user's age identities → tar stream
2. `readTar` extracts entries into the store directory
3. `isWithin` guard rejects entries that escape the store root
4. `O_EXCL` prevents overwriting existing files

On Close:
1. `writeTar` packs non-dotfile, non-coffin entries from the store directory
2. `age.Encrypt` with recipients from `.age-recipients` or `.gpg-id`
3. Atomic write: tmp file → fsync → rename → replaces old coffin
4. `shredDir` overwrites plaintext files with random data, then removes them
5. State file removed

## State file

Location: `$XDG_DATA_HOME/binpass/<basename>-tomb.state` (or `$BINPASS_DATA_DIR`).

The state file is stored **outside** the store directory so that git and cloud
sync never pick it up. It is keyed by `filepath.Base(abs)` of the store
directory's absolute path.

```json
{
  "backend": "coffin",
  "store_dir": "/home/user/.password-store",
  "coffin_path": "/home/user/.password-store/store.coffin.age",
  "opened_at": "2026-08-09T14:30:00Z",
  "timer": 3600000000000,
  "pid": 12345
}
```

### Stale state detection

If the process that opened the tomb crashes without closing, the state file
remains. The next Open call detects this:

1. `loadState` reads the state file
2. `IsStale()` checks whether the PID is still alive via `syscall.Kill(pid, 0)`
3. ESRCH → process dead → stale → remove state file, proceed with open
4. EPERM → process alive (different UID) → not stale → `ErrAlreadyOpen`
5. nil → process alive (same UID) → not stale → `ErrAlreadyOpen`

On Windows, `pidIsDead` always returns false (conservative: assumes alive).
Crash recovery on Windows requires `binpass doctor`.

## Auto-close watcher

### Linux

```
┌─────────────┐
│   Watcher   │
├─────────────┤
│ timerLoop   │─── time.After(timer) ───▶ triggerClose()
│             │
│ sessionBus  │─── ActiveChanged(true) ─▶ triggerClose()
│  (D-Bus)    │    GNOME ScreenSaver
│             │    freedesktop ScreenSaver
│             │
│ systemBus   │─── PrepareForSleep(true) ▶ triggerClose()
│  (D-Bus)    │    logind
└─────────────┘
```

D-Bus connections are established in background goroutines. If the session bus
is unavailable (headless, container), the watcher degrades to timer-only with
no error. `DoctorCheck()` reports which D-Bus services are available.

`triggerClose()` is guarded by a mutex and fires exactly once. After the close
callback returns, the `done` channel is closed, which unblocks `Stop()`.

### macOS / Windows

Timer only. Screen lock detection (IOKit, WinAPI) is planned.

## CLI commands

```
binpass tomb init   [--type=coffin|luks|sparsebundle] [--size=1G] [--recipient=age1...]
binpass tomb open   [--timer=1h]
binpass tomb close  [--force]
binpass tomb status
```

| Flag | Command | Description |
|------|---------|-------------|
| `--type` | init | Backend type. Default: coffin |
| `--size` | init | Container size for LUKS/sparsebundle (e.g. 1G, 512M) |
| `--recipient`, `-r` | init | Age recipient string. Falls back to store's `.age-recipients` |
| `--timer` | open | Auto-close duration (e.g. 30m, 1h). Empty = disabled |
| `--force` | close | Close even if the store appears unchanged (reserved, not yet wired) |

The `tomb open` command blocks the terminal until SIGINT/SIGTERM or the
auto-close fires. This keeps the process alive so the watcher goroutines can
run. On signal, `watcher.Stop()` is called to clean up D-Bus connections.

## Security properties

### At rest
- Only `store.coffin.age` and dotfiles (`.age-recipients`, `.gpg-id`, `.git/`)
  are visible in the store directory.
- No file names, no directory structure, no metadata leaks from the archive.
- Age provides authenticated encryption; tampered ciphertexts fail decryption.

### During session (open)
- Plaintext files exist on disk (tmpfs on Linux, 0700 directory elsewhere).
- `mlockDir` (Linux) prevents small files (< 64KB) from being swapped.
- Auto-close (timer + screen lock + suspend) limits the exposure window.
- State file (sidecar) records PID and timestamp for crash detection.

### On close
- Plaintext files are overwritten with `crypto/rand` data before removal.
- Coffin is written atomically (tmp → fsync → rename) — crash during close
  leaves the old coffin intact.
- Dotfiles survive close by design: `.age-recipients` and `.gpg-id` are needed
  for the next open, `.git/` for sync.

### Known limitations

- **SSD shred**: `overwriteRandom` writes random bytes over each file, but SSD
  wear-leveling may remap the physical block. No guarantee of physical
  destruction. The CLI prints a warning on close.
- **Plaintext exposure window**: the coffin backend cannot avoid having plaintext
  on disk during the session. Use LUKS (when implemented) for stronger
  guarantees.
- **No filesystem lock**: concurrent Open calls from two processes can race.
  `O_EXCL` provides partial protection (second unpack fails on existing files),
  but the state file may end up inconsistent. Single-user local tool assumption
  makes this unlikely.
- **State file collision**: `filepath.Base(abs)` means two stores sharing a
  directory name (e.g. `~/a/store` and `~/b/store`) collide on the state file.
  Future: hash the full absolute path.
- **Recipient trust**: `readRecipients` reads `.age-recipients` from the store
  directory on every Close. If the file is modified between Open and Close, the
  coffin is re-encrypted for the new recipients. In the single-user threat model,
  anyone who can modify `.age-recipients` already has access to the plaintext.

## Dependencies

- `filippo.io/age` — age encryption/decryption
- `github.com/godbus/dbus/v5` — D-Bus auto-close (Linux only, pure Go, no CGO)
- `archive/tar` — tar archive format (stdlib)
- `crypto/rand` — random data for shred (stdlib)

## Tests

| File | Scope | Coverage |
|------|-------|----------|
| `tomb_test.go` | Backend selection, lifecycle, state, shredDir, hasPlaintext | Unit |
| `coffin_test.go` | Tar round-trip, path traversal, encrypt/decrypt, overwrite, watcher, crash recovery | Integration |
| `e2e_test.go` | Full lifecycle, content survival, crash recovery, timer, shred, nested dirs, permissions | E2E |

Key test scenarios:
- Full lifecycle: init → open → modify → close → open → verify
- Content modifications survive close/open cycles
- Deleted entries disappear after close/open
- Double open rejected with `ErrAlreadyOpen`
- Close without open rejected with `ErrNotOpen`
- Crash recovery: state file left behind → next Open detects stale PID → cleanup → proceed
- No plaintext remains after close (directory listing verified)
- Timer auto-close fires and closes the tomb
- Shred overwrites file content (read back after overwrite, verify not original)
- Empty store works
- Nested directory structure preserved
- File permissions preserved across close/open
- `.age-recipients` must exist for Close to find recipients
- `SelectBackend` rejects unknown backend names
- `DefaultBackend` returns coffin

## Platform build matrix

| File | linux | darwin | windows |
|------|-------|--------|---------|
| `tomb.go` | ✅ | ✅ | ✅ |
| `coffin.go` | ✅ | ✅ | ✅ |
| `state.go` | ✅ | ✅ | ✅ |
| `watcher_linux.go` | ✅ | — | — |
| `watcher_other.go` | — | ✅ | ✅ |
| `mlock_linux.go` | ✅ | — | — |
| `mlock_other.go` | — | ✅ | ✅ |
| `pid_unix.go` | ✅ | ✅ | — |
| `pid_windows.go` | — | — | ✅ |
| `luks_linux.go` | ✅ | — | — |
| `luks_other.go` | — | ✅ | ✅ |
| `sparsebundle_darwin.go` | — | ✅ | — |
| `sparsebundle_other.go` | ✅ | — | ✅ |

All builds use `CGO_ENABLED=0`. The `godbus/dbus/v5` dependency is pure Go
and compiles on all platforms; the `watcher_linux.go` file uses build tags to
restrict D-Bus code to Linux.
