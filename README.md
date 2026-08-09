# binpass

`pass(1)`, reimagined. The same storage format and the same command surface,
but everything people install a dozen bash extensions for is built in and works
the same way on Linux, macOS and Windows.

* Same store layout as pass: a directory tree, `.gpg-id`, `.age-recipients`.
* Same stdout, byte for byte, so `passmenu`, `rofi-pass`, `browserpass` and
  QtPass keep working.
* GPG **and** age side by side in one tree, chosen per entry by file extension.
* Hardware keys through the standard age-plugin protocol.
* A single static binary, `CGO_ENABLED=0`.

Compatibility is not a claim, it is a test: the suite runs the real `pass`
against binpass on an identical store and compares stdout, exit codes and the
resulting tree. See [Compatibility](#compatibility).

## Status

Implemented so far: the complete pass command surface, age and GPG backends,
one-time passwords, the built-in picker, plugins, the encrypted tomb, import
and export, and auditing. The Secret Service provider and the full-screen TUI
are specified in [ARCHITECTURE.md](ARCHITECTURE.md) but not yet written.

| Working | Command |
|---|---|
| yes | `init` `ls` `show` `find` `grep` `insert` `edit` `generate` `rm` `mv` `cp` `git` `version` |
| yes | `otp` (pass-otp), `menu` (passmenu / rofi-pass), `generate --words` (diceware) |
| yes | `plugin` — any executable named `binpass-*` on `PATH` becomes a subcommand |
| yes | `tomb` (pass-tomb), `doctor` |
| yes | `import` (pass-import, 9 formats), `export` (CSV), `audit` (pass-audit), `binary` (pass-file) |
| yes | `sync` `remote` `conflicts` `fsck` |
| not yet | `ss` `tui` |

## Plugins

Drop an executable named `binpass-foo` on your `PATH` and `binpass foo` runs
it, the same way `kubectl` and `git` work. Arguments and flags pass through
untouched, and the plugin's exit status becomes binpass's.

```sh
printf '#!/bin/sh\necho "hello, $*"\n' > ~/.local/bin/binpass-hello
chmod +x ~/.local/bin/binpass-hello
binpass hello world          # hello, world

binpass plugin list          # what binpass can see, and what will not run
```

Plugins call back into binpass through `$BINPASS_BIN` with `--format=json`,
so they never parse output meant for humans. See [docs/plugins.md](docs/plugins.md),
which includes an honest account of what the plugin boundary does and does
not protect.

## Install

```sh
go install github.com/71g3pf4c3/binpass/cmd/binpass@latest
```

Or with Nix:

```sh
nix run github:71g3pf4c3/binpass
nix develop            # dev shell with go, gpg, pass, age, rofi, fzf
```

## Quick start

```sh
# A new store, encrypted with age.
age-keygen -o ~/.config/binpass/identities.age
binpass init --age age1qz...

# Or drop in next to an existing pass store; nothing needs converting.
binpass init --gpg you@example.com

binpass insert github.com/alice
binpass generate -c bank/tinkoff 32
binpass show github.com/alice
binpass otp github.com/alice
```

## Import and export

Move passwords from another manager into binpass. Auto-detection means you don't
need to know the format — just point `binpass import` at the export file.

```sh
# Import a CSV or KDBX file (format detected automatically).
binpass import bitwarden_export.csv
binpass import keepass.kdbx              # prompts for database password

# See what would be imported without writing anything.
binpass import --dry-run bitwarden_export.csv

# Force-overwrite entries that already exist.
binpass import --force bitwarden_export.csv

# Specify the format explicitly when auto-detection fails.
binpass import --format=1password export.csv

# Handle non-UTF-8 exports (e.g. Russian LastPass).
binpass import --encoding=windows-1251 lastpass.csv
```

Supported formats: **Bitwarden, 1Password, LastPass, Chrome, Firefox, Enpass,
KeePass (KDBX), pass, gopass**.

Export the entire store to CSV. The output contains decrypted passwords in plain
text — delete the file after use and never commit it.

```sh
binpass export                           # to stdout
binpass export backup.csv               # to file
```

## Audit

Check the store for weak, reused, expired, and breached passwords.

```sh
# Full audit (includes HIBP breach check, requires network).
binpass audit

# Offline audit (skip the HIBP check).
binpass audit --no-hibp

# JSON output for scripting.
binpass audit --format=json

# Parallel decryption (faster, but bad for hardware tokens).
binpass audit --parallel=4
```

The HIBP check uses the k-anonymity protocol: only the first 5 characters of the
SHA-1 hash are sent to the API. The full password hash never leaves the machine.
Passwords are never printed in the output — only entry names and verdicts.

## Binary secrets

`binpass binary` replaces `pass-file`. Binary entries are stored as base64-encoded
`.b64` entries (gopass convention), so they are versioned, synced, and re-encrypted
alongside text secrets.

```sh
# Store a binary file in the password store.
binpass binary copy photo.b64 photo.jpg

# Decode and write back to disk.
binpass binary cat photo.b64 > photo.jpg

# Check the SHA-256 of the decoded content.
binpass binary sum photo.b64

# Store and delete the original (like git mv).
binpass binary move key.b64 /path/to/key.pem
```

`binpass` reads every `PASSWORD_STORE_*` variable pass understands. The
matching `BINPASS_*` variable wins where both are set.

## Interactive pickers

`binpass menu` replaces `passmenu`, `rofi-pass` and `fzf-pass` without a
wrapper script. It detects rofi, wofi, dmenu, wmenu or fzf, and never decrypts
anything until an entry is actually chosen.

```sh
binpass menu                       # pick, copy the password
binpass menu --field=username      # copy a field instead
binpass menu --type                # type it into the focused window
binpass menu --launcher=fzf        # force a picker
binpass menu -- -theme solarized   # arguments after -- go to the launcher
```

Bind it to a key:

```
# sway
bindsym $mod+p exec binpass menu
bindsym $mod+Shift+p exec binpass menu --type

# i3
bindsym $mod+p exec --no-startup-id binpass menu
```

### Building your own

`--format=plain` and `--format=json` exist precisely so launcher scripts never
have to parse the tree output:

```sh
binpass ls --format=plain | rofi -dmenu -i -p pass
```

That one line is the core of `rofi-pass`. If `binpass menu` does not do what
you want, a complete rofi-pass equivalent is short enough to keep in your
dotfiles. Name it `binpass-rofi`, put it on your `PATH`, and it becomes
`binpass rofi`:

```bash
#!/usr/bin/env bash
set -euo pipefail

entry=$(binpass ls --format=plain | rofi -dmenu -i -p pass) || exit 0
action=$(printf 'copy\ntype\nautofill\notp\n' | rofi -dmenu -i -p "$entry") || exit 0

case $action in
copy) binpass show --clip "$entry" ;;
type) binpass show --field=password "$entry" | tr -d '\n' | wtype - ;;
otp)  binpass otp --clip "$entry" ;;
autofill)
	user=$(binpass show --field=username "$entry")
	pass=$(binpass show --field=password "$entry")
	wtype "$user" -k Tab "$pass" -k Return
	;;
esac
```

The upstream `rofi-pass` needs about 900 lines to do this, because pass gives
it nothing to build on: it walks the store itself, parses human-readable
output and drives `gpg` by hand.

binpass ships no launcher scripts of its own. `binpass menu` covers what they
did, and anything it does not cover is a plugin you write in a dozen lines
rather than a script this repository has to keep working on four desktops.

Copying always restores the clipboard's previous contents afterwards, and only
if the secret is still there, so it never clobbers something you copied in the
meantime.

## Storage format

Identical to pass. The first line is the password, everything after it is free
text:

```
hunter2
otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub
url: https://github.com
username: alice
```

`key: value` lines are exposed through `--field`, and any `otpauth://` URI is
picked up by `binpass otp`, but neither is required. A secret round-trips
through binpass byte for byte, including entries with no trailing newline.

GPG and age entries coexist in one tree, selected by extension. A new entry
uses the store's default backend, unless the destination only has recipients
for the other one: a GPG-only store keeps receiving `.gpg` files even when age
is configured as the default, so your existing `pass` never stops working.

## Synchronisation

binpass synchronises your password store across devices without a server. The
sync engine is transport-agnostic: it works identically over git, restic, Google
Drive, Yandex.Disk, WebDAV, and S3. Conflict resolution is automatic and
conservative — nothing is ever lost silently.

### Quick start: git

If your store is already a git repository (most pass users' stores are),
`binpass sync` works out of the box:

```sh
# First sync: detects the git remote in the store automatically.
binpass sync

# Dry run: show what would happen without making changes.
binpass sync --dry-run

# Push and pull are implicit; the engine figures out the direction.
```

The commit messages are identical to pass (`Add given password for X to
store.`), so the history is indistinguishable from a native pass repository.
Your existing `pass git log` output stays clean.

### Adding a git remote

```sh
# The store directory becomes a git repository with a remote.
binpass git init
binpass git remote add origin git@github.com:you/password-store.git
binpass sync
```

### Adding a restic remote

Restic provides encrypted, deduplicated, versioned snapshots of the entire
store. Unlike git, the remote storage sees only opaque encrypted blobs — entry
names are never exposed.

```sh
# Local encrypted backup.
restic init --repo /mnt/backup/binpass
binpass remote add restic local /mnt/backup/binpass
binpass sync --remote=local

# S3 (restic speaks S3 directly, no rclone needed).
restic init --repo s3:s3.amazonaws.com/my-bucket/binpass
binpass remote add restic s3-backup s3:s3.amazonaws.com/my-bucket/binpass
binpass sync --remote=s3-backup
```

For production, store the restic password securely:

```yaml
# ~/.config/binpass/config.yaml
sync:
  remotes:
    s3-backup:
      type: restic
      url: s3:s3.amazonaws.com/my-bucket/binpass
      password_command: "pass show restic/binpass"
```

Each `binpass sync` creates a new restic snapshot. Roll back with
`restic restore` or `binpass sync` from an earlier snapshot.

### Adding a cloud remote

binpass uses [rclone](https://rclone.org/) under the hood for cloud storage.
Install rclone first, then:

```sh
# S3 (MinIO, AWS, Garage, etc.)
binpass remote add s3 mybucket mybucket:password-store

# Google Drive
binpass remote add gdrive gdrive binpass-store

# Yandex.Disk
binpass remote add yandex yandex password-store

# WebDAV (Nextcloud, ownCloud, Synology, etc.)
binpass remote add webdav nextcloud nextcloud:password-store

# Sync with a specific remote.
binpass sync --remote=mybucket
```

rclone configuration is shared with `~/.config/rclone/rclone.conf`. If you
already use rclone, your existing remotes work without any extra setup.

### How conflicts are resolved

When two devices edit the same entry while offline, binpass keeps **both**
copies — it never silently picks a winner:

```
github.com/alice.gpg                                     ← remote version
github.com/alice.conflict-thinkpad-20260808T142233.gpg   ← local version
```

The original path always receives the remote version; the local version is
saved with a `.conflict-<device>-<timestamp>` suffix. Both files are encrypted
with the same recipients as the original entry.

**HOTP counters are auto-merged.** If the only difference between two versions
is the HOTP counter (which diverges by design), binpass takes the maximum and
increments both version vectors. This is the only place where the sync engine
looks inside a secret; everything else operates on ciphertext.

**Delete vs edit: edit wins.** If one device deletes an entry while another
edits it, the edited version is preserved with a warning. A deleted entry that
still has a live version on another device is not lost.

### Managing conflicts

```sh
# List conflict files in the store.
binpass conflicts list

# Show the diff between a conflict file and the current version.
# The password line is masked by default.
binpass conflicts diff github.com/alice.gpg

# Show the full diff including the password.
binpass conflicts diff github.com/alice.gpg --show-secrets

# Resolve: keep the local version (delete conflict file).
binpass conflicts resolve github.com/alice.gpg --strategy=local

# Resolve: keep the remote version (overwrite local with conflict file).
binpass conflicts resolve github.com/alice.gpg --strategy=remote

# Resolve: keep both (the default — conflict file stays).
binpass conflicts resolve github.com/alice.gpg --strategy=both
```

### Remotes configuration

Remotes can be configured in the YAML config file at
`~/.config/binpass/config.yaml`:

```yaml
sync:
  auto: off               # off | on-change | interval
  conflict: keep-both     # keep-both | interactive | prefer-local | prefer-remote
  default_remote: origin  # used when --remote is not specified

  remotes:
    origin:
      type: git
      url: git@github.com:you/password-store.git
    s3-backup:
      type: s3
      url: mybucket:password-store
    gdrive:
      type: gdrive
      url: gdrive
      folder: binpass-store
    yandex:
      type: yandex
      url: yandex
      folder: password-store
    webdav:
      type: webdav
      url: nextcloud:password-store
```

Environment variable overrides (take priority over the config file):

| Variable | Config key | Example |
|---|---|---|
| `BINPASS_SYNC_AUTO` | `sync.auto` | `on-change` |
| `BINPASS_SYNC_CONFLICT` | `sync.conflict` | `prefer-local` |
| `BINPASS_SYNC_DEFAULT_REMOTE` | `sync.default_remote` | `s3-backup` |

### State directory

The sync state database lives **outside** the password store, at
`$XDG_STATE_HOME/binpass/` (default `~/.local/state/binpass/`). This is
critical: if state.db were inside the store, it would end up in git history
and on cloud drives, and `pass git status` would show noise.

Override with `BINPASS_STATE_DIR`:

```sh
export BINPASS_STATE_DIR=~/.binpass-state
```

### Consistency check

```sh
# Check the store against the state database.
binpass fsck
```

`fsck` reports:

- **Untracked files** — on disk but not in state.db (e.g. created outside binpass).
- **Orphaned state** — in state.db but not on disk (e.g. deleted outside binpass).
- **Size drift** — file size differs from what state.db recorded.
- **State in store** — state.db is inside the password store (critical leak risk).
- **Missing recipients** — no `.gpg-id` or `.age-recipients` file found.

Errors cause a non-zero exit code; warnings are informational.

### How it works

The sync engine uses **version vectors** (one counter per device) to detect
divergence without a central clock:

1. **Scan** the local store: `(size, mtime)` for quick detection, blake3 hash
   of the **ciphertext** for confirmation.
2. **List** the remote: build a remote snapshot from the transport.
3. **Load** the base snapshot: the state at the last successful sync, stored
   in state.db.
4. **Merge**: compare local, remote, and base. Version vectors determine the
   action (push, pull, conflict, merge, or nothing).
5. **Apply**: upload, download, or create conflict files. Each action updates
   state.db independently, so a failure halfway through is resumable.
6. **Record**: persist the new base snapshot.

All state mutations go through a write-ahead log (bbolt). If the process is
killed mid-sync, the WAL is replayed on the next run and the state is
recovered automatically.

## Compatibility

The golden suite installs the real `pass` and runs both programs over identical
stores:

```
TestListingMatchesPass              tree output, byte for byte
TestShowPreservesExactBytes         entries without a trailing newline
TestTreeLayoutIsByteIdentical       every connector and continuation glyph
TestStoreWrittenByBinpassIsReadableByPass
TestStoreWrittenByPassIsReadableByBinpass
```

`tree(1)` picks its glyphs from the locale codeset and its colours from `TERM`;
binpass reproduces both decisions rather than hardcoding one, which is why the
output matches inside a container as well as on a desktop.

**Known deviation.** For `rm`, `mv` and `cp`, pass shells out to `rm -v`,
`mv -v` and `cp -v` and passes coreutils' progress chatter straight through,
absolute paths and all. binpass performs the same operations and produces the
same tree, but does not reproduce that output. Nothing in the ecosystem parses
it.

**Not supported.** pass extensions written in bash that source pass's internals.
Everything they do is available natively; see ARCHITECTURE.md §5.

## Development

```sh
nix develop          # go, gpg, pass, age, tree, rofi, fzf, linters
make test
make cover
```

The dev shell unsets any `PASSWORD_STORE_*` your own session exports, so tests
measure the code rather than the machine.

Run the suite against a plain Debian userland with the distro's own `pass`:

```sh
docker build -f Dockerfile.test -t binpass-test .
docker run --rm binpass-test
```

## Licence

MIT. See [LICENSE](LICENSE).
