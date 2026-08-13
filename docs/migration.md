# Migration Guide: GPG ↔ age, Backends, Tomb

How to move a password store between encryption backends, set up remote
synchronisation, and hide the store at rest.

---

## Contents

1. [Current state and prerequisites](#1-current-state-and-prerequisites)
2. [Installing age and generating an identity](#2-installing-age-and-generating-an-identity)
3. [Init: GPG store](#3-init-gpg-store)
4. [Migration GPG → age](#4-migration-gpg--age)
5. [Migration age → GPG](#5-migration-age--gpg)
6. [Sync backends](#6-sync-backends)
7. [Tomb](#7-tomb)
8. [Practical migration plan](#8-practical-migration-plan)

---

## 1. Current state and prerequisites

A typical starting point:

- A `pass`-format store at `~/.password-store`, initialised with GPG.
- `.gpg-id` contains a GPG key identifier (e.g. `secret1`).
- All entries are `.gpg` files.
- A git remote already configured.

What you need before starting:

- `binpass` installed and on `PATH`.
- `age` installed (only if migrating to or from age).
- `gpg` installed and the secret key available (only if GPG is involved).
- `git` for the default sync transport.
- `restic` if you plan to use restic remotes.
- `rclone` if you plan to use cloud remotes (S3, Google Drive, Yandex.Disk, WebDAV).

---

## 2. Installing age and generating an identity

Install:

```sh
# Nix
nix profile install nixpkgs#age

# Debian / Ubuntu
sudo apt install age

# macOS
brew install age
```

Generate an identity file:

```sh
mkdir -p ~/.local/share/binpass
age-keygen -o ~/.local/share/binpass/identities.age
chmod 600 ~/.local/share/binpass/identities.age
```

Extract the public recipient:

```sh
age-keygen -y ~/.local/share/binpass/identities.age
# age1qz...
```

This recipient string is what goes into `.age-recipients` and `binpass init --age`.

### Hardware tokens

If you have a YubiKey or NitroKey, you can use `age-plugin-yubikey` instead of
a file-based identity:

```sh
nix profile install nixpkgs#age-plugin-yubikey
age-plugin-yubikey   # provision a key on the token
```

The plugin prints an `age1yubikey1...` recipient. Use it in `binpass init --age`.
Decryption requires the token to be plugged in and (optionally) a PIN or touch.

Other supported plugins:

| Token | Plugin |
|---|---|
| YubiKey / NitroKey (PIV) | `age-plugin-yubikey` |
| Any FIDO2 token | `age-plugin-fido2-hmac` |
| TPM 2.0 | `age-plugin-tpm` |
| Apple Secure Enclave | `age-plugin-se` |

---

## 3. Init: GPG store

From scratch:

```sh
binpass init --gpg you@example.com
```

This creates `.gpg-id` in the store directory. New entries are encrypted to the
GPG key(s) listed there.

If the store already exists (most pass users' stores do), nothing needs to be
done — binpass reads the same `.gpg-id` that `pass` uses.

---

## 4. Migration GPG → age

### 4.1 Hybrid mode (recommended first step)

binpass supports GPG and age entries in the same tree. The encryption backend
is chosen per entry by file extension: `.gpg` → GPG, `.age` → age. Existing
`.gpg` files are left untouched; only new entries use the new backend.

Steps:

```sh
# 1. Generate an age identity (see §2).

# 2. Initialise the age side of the store.
binpass init --age age1qz...
# This writes .age-recipients alongside the existing .gpg-id.
# New entries will be .age files. Existing .gpg files are not touched.

# 3. Verify both backends work.
binpass doctor
```

**Pros:** zero risk, gradual migration, instant rollback (delete `.age-recipients`).
**Cons:** two crypto backends in one tree, GPG dependency does not go away.

### 4.2 Full migration via `binpass reencrypt` (not yet implemented)

The architecture specifies:

```sh
binpass reencrypt --to=age [--dry-run] [path]
```

This would re-encrypt every `.gpg` file as `.age`, update `.age-recipients`,
and remove `.gpg-id`. `--dry-run` would show the plan without making changes.

**Status: not implemented.** When it ships, this will be the recommended path.

### 4.3 Manual migration (works now)

A migration script that re-encrypts each entry:

```sh
#!/usr/bin/env bash
set -euo pipefail

STORE=~/.password-store
RECIPIENT=$(age-keygen -y ~/.local/share/binpass/identities.age)

# 0. Prechecks
binpass doctor
echo "Recipient: $RECIPIENT"
read -p "Continue? [y/N] " confirm
[[ "$confirm" == "y" ]] || exit 1

# 1. Check for subdirectory .gpg-id overrides.
#    If they exist, the insert below may pick GPG instead of age.
#    Either remove them or reinit the subdirectory.
gpg_overrides=$(find "$STORE" -name .gpg-id -not -path '*/.git/*' | wc -l)
if [[ "$gpg_overrides" -gt 1 ]]; then
    echo "WARNING: $gpg_overrides .gpg-id files found (subdirectory overrides)."
    echo "  These may cause insert to use GPG instead of age."
    echo "  Run: find $STORE -name .gpg-id -not -path '*/.git/*' -print"
    read -p "Continue anyway? [y/N] " ok
    [[ "$ok" == "y" ]] || exit 1
fi

# 2. Initialise age in the store.
binpass init --age "$RECIPIENT"

# 3. Re-encrypt each .gpg entry.
while IFS= read -r -d '' gpg_file; do
    rel="${gpg_file#$STORE/}"
    name="${rel%.gpg}"

    # Skip if an .age version already exists.
    [[ -f "$STORE/${name}.age" ]] && continue

    # Decrypt to a tmpfs temp file.
    tmp=$(mktemp --tmpdir=/dev/shm)
    binpass show -f "$name" > "$tmp"

    # Re-encrypt as .age (insert uses the default backend, which is now age).
    binpass insert -f -m "$name" < "$tmp"
    shred -u "$tmp"

    # Remove the .gpg file.
    binpass rm -f "$name"

    echo "migrated: $name"
done < <(find "$STORE" -name '*.gpg' -not -path '*/.git/*' -print0)

# 4. Remove .gpg-id (only after verifying all entries are .age).
remaining=$(find "$STORE" -name '*.gpg' -not -path '*/.git/*' | wc -l)
if [[ "$remaining" -eq 0 ]]; then
    rm "$STORE/.gpg-id"
    echo "Removed .gpg-id. Store is now age-only."
else
    echo "WARNING: $remaining .gpg files remain. Not removing .gpg-id."
fi

# 5. Commit.
binpass git add -A
binpass git commit -m "Migrate store from GPG to age"
```

**Risks and caveats:**

- `binpass show` + `binpass insert` passes plaintext through a pipe and a temp
  file on tmpfs. On a single-user machine this is acceptable.
- If the process is killed mid-cycle, the store will be partially migrated: some
  `.gpg`, some `.age`. The script is idempotent (skips entries that already have
  an `.age` file), but you must verify manually after a crash.
- `binpass insert -f -m` uses the store's default backend. After `init --age`
  the default is age, but subdirectory `.gpg-id` files can override this. Check
  with `find $STORE -name .gpg-id -not -path '*/.git/*'`.
- `binpass show -f` outputs raw content including multiline secrets (OTP URIs,
  custom fields). The temp-file approach preserves everything; piping through
  `echo` would lose trailing newlines.

### 4.4 Gradual migration (subtree at a time)

Migrate one directory first, validate, then proceed:

```sh
# Migrate test/ first.
for f in $(find ~/.password-store/test -name '*.gpg' -not -path '*/.git/*'); do
    name="${f#$STORE/}"; name="${name%.gpg}"
    tmp=$(mktemp --tmpdir=/dev/shm)
    binpass show -f "$name" > "$tmp"
    binpass insert -f -m "$name" < "$tmp"
    shred -u "$tmp"
    binpass rm -f "$name"
done

# Verify.
binpass ls test/
binpass show test/some-entry
```

---

## 5. Migration age → GPG

The same process in reverse.

```sh
# 1. Ensure the GPG key is in .gpg-id.
binpass init --gpg you@example.com

# 2. Re-encrypt each .age entry.
STORE=~/.password-store
while IFS= read -r -d '' age_file; do
    rel="${age_file#$STORE/}"
    name="${rel%.age}"

    [[ -f "$STORE/${name}.gpg" ]] && continue

    tmp=$(mktemp --tmpdir=/dev/shm)
    binpass show -f "$name" > "$tmp"
    binpass insert -f -m "$name" < "$tmp"
    shred -u "$tmp"

    binpass rm -f "$name"
done < <(find "$STORE" -name '*.age' -not -path '*/.git/*' -print0)

# 3. Remove .age-recipients.
remaining=$(find "$STORE" -name '*.age' -not -path '*/.git/*' | wc -l)
if [[ "$remaining" -eq 0 ]]; then
    rm "$STORE/.age-recipients"
    echo "Removed .age-recipients. Store is now GPG-only."
else
    echo "WARNING: $remaining .age files remain. Not removing .age-recipients."
fi

# 4. Commit.
binpass git add -A
binpass git commit -m "Migrate store from age to GPG"
```

**How the backend is chosen:** when both `.gpg-id` and `.age-recipients` exist,
the default for new entries is determined by the `--age` / `--gpg` flag passed
to `init`, or by `config.yaml: crypto.default`. Removing one of the two files
makes the choice unambiguous.

---

## 6. Sync backends

### 6.1 git (default)

If the store is already a git repository, `binpass sync` detects the `origin`
remote automatically.

```sh
binpass sync                # pull + merge + push
binpass sync --dry-run      # preview
```

From scratch:

```sh
binpass git init
binpass git remote add origin git@github.com:you/password-store.git
binpass sync
```

**What the provider sees:** file names, directory structure, commit history.
Content is encrypted, but metadata (which sites you have accounts with) is
visible. This is an inherent property of the pass format.

### 6.2 restic

Encrypted, deduplicated, versioned snapshots. The storage provider sees only
opaque blobs — file names and directory structure are encrypted by restic.

```sh
# Local repository.
restic init --repo /mnt/backup/binpass
binpass remote add restic local-restic /mnt/backup/binpass
binpass sync --remote=local-restic

# S3 (any S3-compatible: AWS, MinIO, Garage, Ceph, Selectel).
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
restic init --repo s3:https://s3.example.com/bucket/binpass
binpass remote add restic s3-backup s3:https://s3.example.com/bucket/binpass
binpass sync --remote=s3-backup

# SFTP.
restic init --repo sftp:user@server:/backup/binpass
binpass remote add restic sftp-backup sftp:user@server:/backup/binpass
binpass sync --remote=sftp-backup
```

Every restic backend works: `s3:`, `b2:`, `azure:`, `gs:`, `swift:`, `rest:`,
and `rclone:` (which reaches Google Drive, Dropbox, OneDrive, etc. with
deduplication and snapshots on top).

```sh
# restic through rclone → Google Drive.
binpass remote add restic drive "rclone:gdrive:binpass"
```

**Password management:** do not put the restic password in `config.yaml` in
plaintext. Use `password_command`:

```yaml
sync:
  remotes:
    s3-backup:
      type: restic
      url: s3:https://s3.example.com/bucket/binpass
      password_command: "binpass show restic/s3-backup"
```

Or use the environment variable:

```sh
export RESTIC_PASSWORD_FILE=/path/to/keyfile
```

**Snapshot management:**

```sh
restic snapshots --repo s3:https://s3.example.com/bucket/binpass
restic restore abc12345 --repo ... --target /tmp/restore
restic forget --keep-within 30d --prune --repo ...
```

### 6.3 Cloud (rclone-based)

For when you need the store to be readable as ordinary files at the far end.
If you do not need that, restic over the same provider is the better choice.

```sh
# S3 via rclone.
binpass remote add s3 mybucket mybucket:password-store

# Google Drive.
binpass remote add gdrive gdrive gdrive:binpass-store

# Yandex.Disk.
binpass remote add yandex yandex yandex:password-store

# WebDAV (Nextcloud, ownCloud, Synology).
binpass remote add webdav nextcloud nextcloud:password-store
```

**What the provider sees:** encrypted `.gpg` / `.age` files, but entry names
are visible. Use tomb (§7) or restic to hide metadata.

### 6.4 Combining git and restic

Git for everyday sync, restic for encrypted backup:

```yaml
sync:
  default_remote: origin
  remotes:
    origin:
      type: git
    s3-backup:
      type: restic
      url: s3:https://s3.example.com/bucket/binpass
      password_command: "binpass show restic/s3-backup"
```

```sh
binpass sync                    # git
binpass sync --remote=s3-backup # restic
```

### 6.5 What each provider can see

| Transport | File names | Directory structure | Content | History |
|---|---|---|---|---|
| git | visible | visible | encrypted | visible (commits) |
| restic | **encrypted** | **encrypted** | encrypted | encrypted (snapshots) |
| S3 / gdrive / yandex / webdav | visible | visible | encrypted | versioning-dependent |
| restic over rclone | **encrypted** | **encrypted** | encrypted | encrypted (snapshots) |

---

## 7. Tomb

Hide the entire store at rest: no file names, no directory structure, no
metadata. When the tomb is closed, the store directory holds one encrypted
blob and nothing else.

### 7.1 Coffin (default, cross-platform, no root)

One age-encrypted tar archive. Works on Linux, macOS, and Windows.

```sh
binpass tomb init               # create the archive
binpass tomb close              # hide the store
binpass tomb open --timer=1h    # work with the store
```

While the tomb is open, plaintext lives in a directory (tmpfs on Linux). While
closed, only `store.coffin.age` is visible.

The archive is encrypted to the store's own recipients, so a hardware token
that already unlocks your entries unlocks the tomb too — no second password.

### 7.2 LUKS (Linux, maximum protection, requires root)

A dm-crypt container via `cryptsetup`. Decrypted data exists only in the
kernel's mapping and never lands in a file on disk.

```sh
sudo binpass tomb init --type=luks --size=1G
sudo binpass tomb open
# ... use the store ...
sudo binpass tomb close
```

The container key is random and stored in `store.luks.key.age`, encrypted to
the store's own recipients. Unlocking the tomb is an ordinary age decryption.

`--size` is fixed at creation and the file is sparse (only used space is
allocated). Minimum 16 MB.

**Compatibility with pass-tomb:** not compatible. `pass-tomb` uses the
`tomb(1)` format; this is plain LUKS2 with an age-encrypted key file.

### 7.3 Sparse bundle (macOS only, no root)

An encrypted APFS disk image via `hdiutil`. Like LUKS, plaintext lives in a
mounted filesystem, not a directory that must be shredded. Unlike LUKS, it
does not need root.

```sh
binpass tomb init --type=sparsebundle --size=1G
```

### 7.4 Auto-close

```sh
binpass tomb open --timer=30m
```

On Linux, the tomb also closes on screen lock (D-Bus) and suspend (logind).
macOS and Windows are timer-only.

Check what was detected:

```sh
binpass doctor
```

### 7.5 Syncing a store with a tomb

**Close the tomb before syncing, not after.** With it open, the store is a
directory of entries and the transport uploads each one — precisely the
metadata the tomb exists to hide. Worse, the two states interleave badly:
syncing an open tomb and then closing it makes the next sync look like every
entry was deleted at once.

```sh
binpass tomb close
binpass sync
```

### 7.6 Which tomb backend suits which transport

| | git | restic | rclone (S3, Drive, WebDAV) |
|---|---|---|---|
| **coffin** | fine | **best** | fine |
| **luks** | avoid | **best** | avoid |
| **sparsebundle** | avoid | **best** | avoid |
| no tomb | best | fine | fine |

git keeps every version in full, and encrypted blobs do not delta-compress.
A 1 GB LUKS image edited daily grows the repository by 1 GB per day. restic
deduplicates at the block level: one changed entry rewrites the blocks that
changed, not the whole image.

---

## 8. Practical migration plan

Step-by-step for an existing GPG store moving to age with restic backup and
tomb.

### 8.1 Install and generate

```sh
# Install age.
nix profile install nixpkgs#age

# Generate an age identity.
mkdir -p ~/.local/share/binpass
age-keygen -o ~/.local/share/binpass/identities.age
chmod 600 ~/.local/share/binpass/identities.age

# Extract the recipient.
age-keygen -y ~/.local/share/binpass/identities.age
# age1qz...
```

### 8.2 Hybrid init

```sh
binpass init --age age1qz...
binpass doctor
```

At this point both `.gpg-id` and `.age-recipients` exist. New entries are `.age`.
Existing `.gpg` entries are untouched.

### 8.3 Test migration on a subtree

```sh
STORE=~/.password-store
for f in $(find "$STORE/test" -name '*.gpg' -not -path '*/.git/*'); do
    name="${f#$STORE/}"; name="${name%.gpg}"
    [[ -f "$STORE/${name}.age" ]] && continue
    tmp=$(mktemp --tmpdir=/dev/shm)
    binpass show -f "$name" > "$tmp"
    binpass insert -f -m "$name" < "$tmp"
    shred -u "$tmp"
    binpass rm -f "$name"
done

# Verify.
binpass ls test/
binpass show test/some-entry
```

### 8.4 Full migration

Run the migration script from §4.3, or migrate directory by directory.

After migration, verify:

```sh
# No .gpg files remain.
find ~/.password-store -name '*.gpg' -not -path '*/.git/*' | wc -l
# Expected: 0

# All entries decrypt.
binpass audit --no-hibp
```

### 8.5 Remove GPG

```sh
rm ~/.password-store/.gpg-id
binpass git add -A
binpass git commit -m "Migrate store from GPG to age"
```

### 8.6 Set up restic remote

```sh
# Local.
restic init --repo /mnt/backup/binpass
binpass remote add restic local-restic /mnt/backup/binpass
binpass sync --remote=local-restic

# Or S3.
restic init --repo s3:https://s3.storage.selcloud.ru/container/binpass
binpass remote add restic selectel-s3 s3:https://s3.storage.selcloud.ru/container/binpass
binpass sync --remote=selectel-s3
```

### 8.7 Enable tomb

```sh
binpass tomb init --type=coffin
binpass tomb close
binpass sync --remote=selectel-s3   # pushes the single blob
```

### 8.8 Day-to-day workflow

```sh
binpass tomb open --timer=1h        # terminal 1
# ... work in terminal 2 ...
# Ctrl-C in terminal 1
binpass sync --remote=selectel-s3   # push the updated blob
```

---

## 9. Rollback

If something goes wrong during migration:

- **Before removing `.gpg-id`:** delete `.age-recipients`. The store reverts
  to GPG-only. Any `.age` files created during the attempt remain, but new
  entries will be GPG again.
- **After removing `.gpg-id`:** restore it from git. The `.gpg` files are gone
  (removed by the migration script), but git history has them. Check out the
  previous commit and re-encrypt.
- **Tomb rollback:** `binpass tomb close` re-encrypts and removes plaintext.
  If the tomb was never opened, nothing changed.
