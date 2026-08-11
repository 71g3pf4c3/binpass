# Sync Engine — Implementation Changelog

## 2026-08-09: Restic transport

### Added

- `pkg/remote/restic.go`: ResticRemote — encrypted, deduplicated, versioned
  snapshot transport. Store IS the backup source (like GitRemote). Mutations
  modify the local store; `Push()` creates a new restic snapshot via
  `restic backup`. `List()`/`Get()` read from the latest snapshot via
  `restic ls --json` / `restic dump`. Conditional write via snapshot ID drift
  detection. Entry names are never exposed to the storage provider.

  Public API beyond the Remote interface:
  - `Snapshots(ctx)`: list all snapshots (point-in-time recovery)
  - `Restore(ctx, snapshotID, targetDir)`: restore a full snapshot with
    path translation (restic stores absolute paths; restored files are placed
    in store-relative layout)
  - `Forget(ctx, policyArgs...)`: prune old snapshots with `restic forget --prune`

  Path handling: `restic ls` returns absolute paths from the backup root.
  `toStoreRelative()` strips the storeDir prefix. `toSnapshotPath()` prepends
  it for `restic dump`. `Restore()` uses a staging directory and `resticMoveAll()`
  to translate the restored absolute path tree into store-relative layout.

  Caps: `Atomic=false, WeakAtomic=true, History=true, Locking=false, Rename=true,
  Watch=false`. Snapshot-based conditional write replaces advisory locking.

- `pkg/remote/restic_test.go`: 5 integration tests + 1 validation test.
  Requires `restic` on PATH; skipped in `-short` mode.
  - `TestResticRemote_Integration`: full lifecycle (Put→Push→List→Get→Rename→
    Delete→Snapshots→Restore→Lock→Pull)
  - `TestResticRemote_ConditionalWrite`: two-client snapshot drift detection
  - `TestResticRemote_PutConditionalConflict`: Put with stale snapshot rev
  - `TestResticRemote_Forget`: 3 snapshots → keep 1 → verify
  - `TestResticRemote_NewResticRemoteValidation`: input validation

- `pkg/remote/remote.go`: `RemoteFromConfig("restic", ...)` → `NewResticRemote`

- `internal/cli/sync.go`: `buildRemote()` case "restic" with PasswordCommand
  and Password support. Explicit `rp.Push(ctx)` after `applyActions()` for
  restic remotes (creates snapshot of the local store).

- `internal/config/config.go`: `RemoteConfig.Password`, `RemoteConfig.PasswordCommand`
  fields for restic repository password management.

- `internal/config/file.go`: parse `password` and `password_command` from YAML
  `sync.remotes.<name>` entries.

- `internal/cli/remote.go`: `restic` in valid remote types. YAML I/O includes
  `password` and `password_command` fields.

- `docs/sync-remotes.md` §2: restic section (10 subsections) — how it works,
  prerequisites, local/S3/SFTP repositories, password management, snapshot
  management, privacy (provider sees only opaque blobs), conditional writes,
  limitations.

- `docs/sync-remotes.md` overview table: restic row added.

- `docs/sync-remotes.md` §7 config reference: restic remote examples with
  `password_command`.

- `docs/sync-remotes.md` §8 security: restic noted as strongest privacy option
  (entry names not visible, unlike git).

- `docs/sync-remotes.md` §9 troubleshooting: restic not found, repo not
  initialised, snapshot drift.

- `README.md` Synchronisation: restic quick start, config example with
  `password_command`.

## 2026-08-08: Sync engine, transports, CLI

### Added

- `pkg/sync`: full two-way merge engine (83.9% coverage).
  - `version.go`: VersionVector with device-scoped counters, merge, dominance, equality.
  - `merge.go`: 3-way merge with base snapshot, §8.5 conflict table, HOTP auto-merge
    (max counter), ConflictName helper, delete-vs-edit (edit wins).
  - `scan.go`: store scanner with size+mtime+blake3 change detection. Primary
    detector is (Size, ModTime); hash confirms when metadata differs.
  - `state.go`: FileState, Snapshot, Opener interface.
  - `statedb.go`: bbolt StateDB with WAL, CheckStateLocation, DeviceID. WAL replay
    on crash recovery.
  - `fsck.go`: size+hash drift, untracked files, orphaned state, state-in-store
    detection, missing recipients.

- `pkg/remote`: transport layer with four backends.
  - `git.go`: GitRemote with Pull/Push/conditional write. Store IS the git working
    tree. Pass-compatible commit messages. File-level conditional write (last-
    modifying commit SHA, not HEAD).
  - `rclone.go`: RcloneRemote for S3, Google Drive, Yandex.Disk, WebDAV.
  - `stub.go`: MemRemote for testing.
  - `remote.go`: Remote interface, Caps, RemoteFromConfig factory.

- `internal/cli/sync.go`: `binpass sync` with full I/O in applyActions.
  Push (os.ReadFile→rem.Put), Pull (rem.Get→fs.Write durable), Conflict (save
  local as .conflict-* + download remote to orig), Delete, MergeHOTP, ActionNone.
  Git and restic remotes get explicit Push after applyActions.

- `internal/cli/remote.go`: `binpass remote add/remove/list` with direct YAML I/O
  via gopkg.in/yaml.v3 (no viper, no clobber). Atomic write (tmp→rename).

- `internal/cli/conflicts.go`: `binpass conflicts list|diff|resolve` with
  --show-secrets, --strategy.

- `internal/cli/fsck.go`: `binpass fsck` with error/warning severity, exit 1 on
  errors.

- `internal/config/config.go`: SyncConfig, RemoteConfig, StateDir().

- `.gitlab-ci.yml`: 5 stages (lint, test, build, release).

- `docs/sync-remotes.md`: complete remote storage guide (git, restic, S3, Google
  Drive, Yandex.Disk, WebDAV, config reference, security, troubleshooting).

- `README.md`: Synchronisation section with quick start, remotes, conflicts, state
  dir, fsck.

### Design decisions

1. **Version vectors, not timestamps.** Clock skew between devices makes
   last-write-wins unreliable. Version vectors provide causal ordering:
   V1 dominates V2 if V1[i] ≥ V2[i] for all devices and V1 ≠ V2.

2. **(Size, ModTime) primary, hash confirms.** GPG encryption is non-
   deterministic: re-encrypting the same plaintext yields different ciphertext.
   If hash were the primary detector, every re-encryption would look like a
   change. Size+mtime first; hash only when metadata differs.

3. **State.db outside the store.** If state.db were inside the store, it would
   be committed to git, synced to cloud storage, and `pass git status` would
   show noise. `CheckStateLocation()` enforces this at OpenStateDB time.

4. **GitRemote: file-level conditional write.** Using HEAD as the revision would
   block parallel edits to different files. Instead, `fileRev()` returns the
   last commit that modified the specific file. Two clients can edit different
   files concurrently.

5. **ResticRemote: snapshot-based conditional write.** Restic is append-only.
   Each Push creates a new snapshot. The conditional write checks that the
   latest snapshot ID matches what List observed. If another client pushed,
   the ID differs and Push fails with a conflict.

6. **ResticRemote: store IS the backup source.** Like GitRemote, mutations are
   local. Push creates a snapshot of the entire store. This means restic
   deduplication handles unchanged files efficiently.

7. **ResticRemote: path translation.** `restic ls` and `restic dump` use absolute
   paths (the backup source path). `toStoreRelative()` strips the storeDir prefix
   for the sync engine. `toSnapshotPath()` prepends it for `restic dump`.
   `Restore()` uses staging + `resticMoveAll()` to translate the restored tree.

8. **YAML I/O for remote add/remove.** viper.WriteConfig() clobbers the entire
   config file with defaults. Direct YAML I/O via gopkg.in/yaml.v3 modifies only
   the sync.remotes.<name> subtree. Atomic write via tmp→rename.

### Test coverage

| Package | Coverage | Tests |
|---|---|---|
| pkg/sync | 83.9% | 37 |
| pkg/remote | 65.8% | 23 (git: 5, restic: 5, stub: 11, factory: 2) |
| internal/cli | ~16% | 6 (remote add/remove/list) |
| All packages | ✅ | 14/14 green, go vet clean, gofmt clean |
