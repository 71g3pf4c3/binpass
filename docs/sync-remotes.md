# Remote Storage Guide

How to set up and use remote storage backends with `binpass sync`.

## Overview

binpass synchronises your password store with a remote through a **transport**.
All transports implement the same interface, so `binpass sync` works identically
regardless of where your data lives.

| Transport | Type | Atomic | History | Rename | Setup |
|---|---|---|---|---|---|
| git | `git` | yes | yes | yes | Built-in, no extra deps |
| restic | `restic` | no (snapshot-based) | yes (snapshots) | yes (local) | Requires [restic](https://restic.net/). **Reaches every restic backend**: local, SFTP, S3, B2, Azure, GCS, Swift, REST, and anything rclone supports (§2.2.1) |
| S3 | `s3` | no (verify-after-write) | yes (versioning) | no | Requires [rclone](https://rclone.org/) |
| Google Drive | `gdrive` | no (verify-after-write) | yes (revisions) | no | Requires rclone + OAuth |
| Yandex.Disk | `yandex` | no (verify-after-write) | limited | no | Requires rclone + OAuth |
| WebDAV | `webdav` | no (verify-after-write | no | no | Requires rclone |

**Key difference:** git is atomic and supports rename natively. Cloud
transports are not atomic — binpass adds verify-after-write checks
automatically when the transport reports `WeakAtomic` capability.

**The `s3`, `gdrive`, `yandex` and `webdav` types are rclone storing plain
files.** The `restic` type reaches the same providers — including Drive and
Dropbox, through `rclone:` — but with deduplication, snapshots and history
on top. Unless you need the store to be readable as ordinary files at the
far end, restic is the better choice for all of them.

---

## 0. Two machines, end to end

The common case, start to finish. Everything below was run as written.

### 0.1 The first machine

```sh
# A store that already has entries in it.
binpass init --age age1...
binpass insert github.com/alice

# Make it a git repository. Set an identity first: git refuses to commit
# without one, and the failure surfaces later as a confusing sync error.
cd ~/.password-store
git init
git config user.email you@example.com
git config user.name "Your Name"

binpass remote add git origin git@github.com:you/password-store.git
binpass sync
# push   github.com/alice.age
#   uploading github.com/alice.age
#   pushing to remote...
```

### 0.2 The second machine

**Clone the repository; do not run `binpass init`.**

```sh
git clone git@github.com:you/password-store.git ~/.password-store
cd ~/.password-store
git config user.email you@example.com
git config user.name "Your Name"

binpass remote add git origin git@github.com:you/password-store.git
binpass sync
binpass show github.com/alice
# secret1
```

`binpass init` on the second machine would write a fresh `.age-recipients`
and leave you with two stores that disagree about who they are encrypted to.
Cloning brings the recipients file along with the entries, which is what you
want.

Running `binpass sync` into an empty directory does not work either:

```
Error: password store is empty. Try "binpass init".
```

The store has to exist before it can be synchronised. Clone it.

**Your key does not travel with the repository**, and it must not: the
repository holds ciphertext only. Copy the identity file to the second
machine yourself, over a channel you trust:

```sh
# On the first machine.
age -p -o identity.age ~/.local/share/binpass/identities.age   # passphrase-wrapped
# ... move identity.age across, then on the second machine:
age -d -o ~/.local/share/binpass/identities.age identity.age
chmod 600 ~/.local/share/binpass/identities.age
```

A hardware token avoids this step entirely: plug it into either machine and
nothing secret ever has to be copied.

### 0.3 Day to day

```sh
binpass sync              # both directions: pull, merge, push
binpass sync --dry-run    # show the plan, change nothing
```

### 0.4 When both machines changed the same entry

Nothing is overwritten and nothing is lost. The remote version keeps the
original name, and your local one is saved beside it:

```
push   github.com/alice.age
push   github.com/alice.conflict-thinkpad-20260810T204032.age
```

```sh
binpass conflicts list
# github.com/alice.conflict-thinkpad-20260810T204032  (conflict of github.com/alice)

# Compare them. Passwords are masked unless you ask.
binpass conflicts diff github.com/alice.conflict-thinkpad-20260810T204032
# --- github.com/alice.conflict-thinkpad-20260810T204032 (local)
# +++ github.com/alice (remote)
# - ***********
# + ************

binpass conflicts diff --show-secrets github.com/alice.conflict-thinkpad-20260810T204032
```

Then pick one:

```sh
# Keep what this machine had; it goes back under the original name.
binpass conflicts resolve github.com/alice.conflict-... --strategy=local

# Keep what the other machine had; the conflict file is dropped.
binpass conflicts resolve github.com/alice.conflict-... --strategy=remote

# Decide later.
binpass conflicts resolve github.com/alice.conflict-... --strategy=both
```

Sync again afterwards so the other machine sees the resolution.

### 0.5 Checking the store is sound

```sh
binpass fsck
```

Reports entries the sync database does not know about, orphaned state, and —
as an error — a `state.db` that ended up inside the store. A warning about an
untracked file is normal right after you add an entry and before you sync.

---

## 1. git

The default. If your store is already a git repository (and most pass users'
stores are), there is nothing to configure.

### 1.1. Auto-detection

`binpass sync` checks for a `.git` directory in the store. If it finds one, it
uses the `origin` remote automatically:

```sh
cd ~/.password-store
git remote -v
# origin  git@github.com:you/password-store.git (fetch)
# origin  git@github.com:you/password-store.git (push)

binpass sync
# Everything up-to-date.
```

No `binpass remote add` needed — the git remote that already exists in the
store is used directly.

### 1.2. Setting up git from scratch

```sh
# If your store is not a git repo yet:
binpass git init
binpass git remote add origin git@github.com:you/password-store.git
binpass sync
```

### 1.3. Commit messages

binpass produces the same commit messages as pass:

| Action | Message |
|---|---|
| New entry | `Add given password for github.com/alice to store.` |
| Edit entry | `Edit password for github.com/alice using binpass.` |
| Rename | `Rename github.com/alice to github.com/bob.` |
| Delete | `Remove github.com/alice from store.` |

The git history is indistinguishable from a native pass repository. `pass git
log` output stays clean.

### 1.4. Signed commits

To enable GPG-signed commits (same as `pass git config pass.signcommits true`):

```yaml
# ~/.config/binpass/config.yaml
sync:
  remotes:
    origin:
      type: git
      sign_commits: true
```

### 1.5. Credential helpers

binpass calls the system `git` binary, so all credential helpers, ssh-agent
forwarding, custom SSH keys, and proxy settings work automatically. Configure
them as you normally would:

```sh
# Use a specific SSH key for this repo.
cd ~/.password-store
git config core.sshCommand "ssh -i ~/.ssh/id_ed25519_pass"

# Use a credential helper.
git config credential.helper store
```

### 1.6. Multiple git remotes

You can add multiple git remotes and sync with a specific one:

```sh
cd ~/.password-store
git remote add backup git@github.com:you/pass-backup.git
```

```yaml
# ~/.config/binpass/config.yaml
sync:
  remotes:
    backup:
      type: git
      url: /home/you/.password-store
```

```sh
binpass sync --remote=backup
```

---

## 2. restic

Restic provides **client-side encryption**, **deduplication**, and **snapshot
versioning** for the password store. Every `binpass sync` creates a new restic
snapshot, so you can roll back to any previous state.

This is the recommended transport when you need encrypted backups with full
history but don't want a git repository on the remote side. Unlike git, restic
does not expose entry names in the repository — only opaque, encrypted content
blocks.

### 2.1. How it works

The password store directory is the backup source:

1. **List / Get** read from the latest restic snapshot via `restic ls` /
   `restic dump`. The sync engine compares the snapshot contents with the local
   state.
2. **Put / Delete / Rename** modify the local store directory (like git's
   working tree). No data is sent yet.
3. **Push** runs `restic backup` to create a new snapshot of the store. All
   pending changes are captured in a single, atomic snapshot.
4. **Pull** is a no-op — List and Get always read from the latest snapshot on
   demand.

Revision tracking uses the restic snapshot short ID. If another client pushes a
new snapshot between your List and Push, the conditional-write check detects the
drift and the sync engine re-merges.

### 2.2. Prerequisites

- [restic](https://restic.net/) installed on PATH
- A restic repository

### 2.2.1. Every restic backend works

The repository string is passed to restic untouched, so **anything restic can
address, binpass can use**. The sections below cover local, S3 and SFTP
because they are the common cases, not because they are the supported ones.

| Backend | Repository string |
|---|---|
| Local or mounted disk | `/mnt/backup/binpass` |
| SFTP | `sftp:user@host:/srv/binpass` |
| S3, MinIO, Garage, Wasabi, Ceph | `s3:s3.amazonaws.com/bucket/binpass` |
| Backblaze B2 | `b2:bucket:binpass` |
| Azure Blob Storage | `azure:container:/binpass` |
| Google Cloud Storage | `gs:bucket:/binpass` |
| OpenStack Swift | `swift:container:/binpass` |
| REST server (`rest-server`) | `rest:https://host:8000/binpass` |
| **Anything rclone supports** | `rclone:remote:path` |

That last row is worth noticing: it reaches Google Drive, Yandex.Disk,
Dropbox, OneDrive, pCloud, Box and the rest of rclone's list — with restic's
deduplication and snapshots on top, rather than as plain files. For a store
with a tomb that is the combination to want (§7.5).

Credentials come from the environment, exactly as restic documents them, and
binpass passes its environment through:

```sh
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=...   # s3
export B2_ACCOUNT_ID=... B2_ACCOUNT_KEY=...              # b2
export AZURE_ACCOUNT_NAME=... AZURE_ACCOUNT_KEY=...      # azure
export GOOGLE_PROJECT_ID=... GOOGLE_APPLICATION_CREDENTIALS=...  # gs
```

Verify the repository string with restic before handing it to binpass — the
error messages are restic's, and reading them directly is quicker:

```sh
restic -r b2:mybucket:binpass snapshots
```

### 2.3. Local repository

The simplest setup — an encrypted, versioned backup on a local or mounted
disk:

```sh
# Create the repository.
restic init --repo /mnt/backup/binpass
# Enter password: ...

# Add the remote to binpass.
binpass remote add restic local-restic /mnt/backup/binpass

# Sync.
binpass sync --remote=local-restic
```

### 2.4. S3 repository

Restic can use any S3-compatible storage directly (no rclone needed):

```sh
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...

restic init --repo s3:s3.amazonaws.com/my-bucket/binpass
# Enter password: ...

# Add to binpass.
binpass remote add restic s3-backup s3:s3.amazonaws.com/my-bucket/binpass

binpass sync --remote=s3-backup
```

For other S3-compatible storage (MinIO, Garage, etc.), set the endpoint:

```sh
export RESTIC_REPOSITORY=s3:http://localhost:9000/binpass
```

### 2.5. SFTP repository

```sh
restic init --repo sftp:user@server:/backup/binpass

binpass remote add restic sftp-backup sftp:user@server:/backup/binpass
binpass sync --remote=sftp-backup
```

### 2.6. Password management

You can provide the restic password in several ways:

**Password file** (set via environment):
```sh
export RESTIC_PASSWORD_FILE=/path/to/keyfile
```

**Password command** (recommended for production):
```yaml
# ~/.config/binpass/config.yaml
sync:
  remotes:
    s3-backup:
      type: restic
      url: s3:s3.amazonaws.com/my-bucket/binpass
      password_command: "cat /run/secrets/restic-password"
```

**Inline password** (for testing only — avoid in production):
```yaml
sync:
  remotes:
    test:
      type: restic
      url: /tmp/test-repo
      password: test-password
```

### 2.7. Snapshot management

List snapshots:

```sh
restic snapshots --repo s3:s3.amazonaws.com/my-bucket/binpass
```

Restore a specific snapshot:

```sh
restic restore abc12345 --repo s3:s3.amazonaws.com/my-bucket/binpass --target /tmp/restore
```

Prune old snapshots (keep last 30 days):
```sh
restic forget --keep-within 30d --prune --repo s3:s3.amazonaws.com/my-bucket/binpass
```

### 2.8. What the provider sees

Unlike git, restic encrypts **everything**: file names, directory structure,
content, and metadata. The storage provider sees only opaque, deduplicated
content and metadata blobs. Entry names are **not visible** — this is a
significant privacy advantage over the git transport.

### 2.9. Conditional writes

Restic is append-only: each Push creates a new snapshot, never modifying
existing ones. The conditional-write check compares the snapshot ID observed
during List with the latest snapshot ID at Push time. If they differ, another
client has pushed, and the sync engine re-merges the changes.

### 2.10. Limitations

- **No single-file Put**: restic creates whole-store snapshots, not individual
  file uploads. Each Push snapshots the entire store, but deduplication means
  only changed blocks are transferred.
- **No merge**: unlike git, restic has no merge mechanism. The sync engine
  handles conflict detection and resolution, and the result is captured as a
  new snapshot.
- **Restore path translation**: `restic restore` reproduces the absolute path
  structure. binpass handles this internally — restored files are placed in
  store-relative layout.

---

## 3. S3

Works with any S3-compatible storage: AWS S3, MinIO, Garage, Ceph, Backblaze
B2 (S3 mode), DigitalOcean Spaces, etc.

### 2.1. Prerequisites

- [rclone](https://rclone.org/) installed on PATH
- An S3 bucket created
- rclone configured with the bucket credentials

### 3.2. Configure rclone

```sh
rclone config
# n) New remote
# name> mybucket
# Storage> s3
# provider> Minio (or AWS, Garage, etc.)
# env_auth> false
# access_key_id> YOUR_ACCESS_KEY
# secret_access_key> YOUR_SECRET_KEY
# endpoint> https://s3.example.com
# region> us-east-1
```

This creates `~/.config/rclone/rclone.conf` with the `mybucket` remote.

### 3.3. Add the remote to binpass

```sh
binpass remote add s3 mybucket mybucket:password-store
binpass sync --remote=mybucket
```

### 3.4. Example: MinIO (local)

```sh
# Start a local MinIO instance (for testing).
docker run -d -p 9000:9000 -p 9001:9001 \
  -e MINIO_ROOT_USER=admin -e MINIO_ROOT_PASSWORD=admin123 \
  minio/minio server /data --console-address ":9001"

# Configure rclone for the local MinIO.
rclone config create minio s3 \
  provider=Minio \
  env_auth=false \
  access_key_id=admin \
  secret_access_key=admin123 \
  endpoint=http://localhost:9000

# Create a bucket.
rclone mkdir minio:password-store

# Add to binpass and sync.
binpass remote add s3 minio minio:password-store
binpass sync --remote=minio
```

### 3.5. Example: AWS S3

```sh
# Use AWS credentials from the environment.
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_PROFILE=default  # or use env_auth=true in rclone

rclone config create aws-s3 s3 \
  provider=AWS \
  env_auth=true \
  region=eu-west-1

binpass remote add s3 aws-s3 aws-s3:my-password-bucket
binpass sync --remote=aws-s3
```

### 3.6. Versioning

S3 supports bucket versioning. If enabled on the bucket, all versions of each
file are retained. binpass reports `Caps().History = true` for S3, which means
the sync engine can detect and recover from accidental overwrites.

### 3.7. Rate limits

AWS S3 has generous rate limits (3,500 PUT/s per prefix). MinIO has no
built-in limits. For other providers (DigitalOcean Spaces, etc.), binpass
respects `Retry-After` headers automatically through rclone.

---

## 4. Google Drive

### 4.1. Prerequisites

- [rclone](https://rclone.org/) installed on PATH
- A Google account

### 4.2. Configure rclone

```sh
rclone config
# n) New remote
# name> gdrive
# Storage> drive
# client_id> (leave blank for rclone's own)
# client_secret> (leave blank)
# scope> 1 (full access)
# root_folder_id> (leave blank)
# service_account_file> (leave blank)
# auto_confirm> true
```

rclone will open a browser window for OAuth. Authorise access and the token
is saved to `~/.config/rclone/rclone.conf`.

### 4.3. Headless setup

On a machine without a browser (server, CI), use device-flow:

```sh
rclone authorize "drive" --auto-confirm
# Prints a token JSON. Copy it.

# On the headless machine:
rclone config create gdrive drive \
  config_refresh_token=true \
  token='{"access_token":"...","token_type":"Bearer","refresh_token":"...","expiry":"..."}'
```

### 4.4. Add the remote to binpass

```sh
# The folder will be created on first sync if it does not exist.
binpass remote add gdrive gdrive gdrive:binpass-store
binpass sync --remote=gdrive
```

Or specify a folder name:

```sh
binpass remote add gdrive gdrive gdrive:binpass-store --folder=work
```

### 4.5. Important notes

- **Rate limits**: 10 queries/s per user, 10,000 queries/100s. For large
  stores (>1,000 entries), the initial sync may take a few minutes due to
  per-file API calls. Subsequent syncs are delta-based.
- **Duplicate file names**: Google Drive allows two files with the same name
  in the same folder. If binpass detects a duplicate, it creates a conflict
  file rather than guessing which one is correct.
- **What Google sees**: only the encrypted `.gpg` and `.age` files plus
  `.gpg-id` / `.age-recipients`. Entry names are visible (this is an inherent
  property of the pass format). Use tomb/coffin (ARCHITECTURE.md §7) to hide
  the entire tree as a single encrypted blob.

---

## 5. Yandex.Disk

### 5.1. Prerequisites

- [rclone](https://rclone.org/) installed on PATH
- A Yandex account

### 5.2. Configure rclone

```sh
rclone config
# n) New remote
# name> yandex
# Storage> yandex
# client_id> (leave blank for rclone's own)
# client_secret> (leave blank)
```

rclone will open a browser for Yandex OAuth.

### 5.3. Add the remote to binpass

```sh
binpass remote add yandex yandex yandex:password-store
binpass sync --remote=yandex
```

### 5.4. WebDAV fallback

Yandex.Disk also exposes a WebDAV endpoint. If you already have a WebDAV
rclone config, you can use it:

```sh
rclone config create yandex-webdav webdav \
  url=https://webdav.yandex.ru \
  user=you@yandex.ru \
  pass=$(rclone obscure "your-password")

binpass remote add webdav yandex-webdav yandex-webdav:password-store
binpass sync --remote=yandex-webdav
```

The native Yandex backend is preferred — it is faster and does not share the
WebDAV gateway's request limits.

### 5.5. Important notes

- **Rate limits**: Yandex is stricter than Google Drive. The sync engine
  retries with exponential backoff and jitter.
- **What Yandex sees**: same as Google Drive — encrypted files and visible
  entry names.

---

## 6. WebDAV

Works with Nextcloud, ownCloud, Synology, Radicale, SabreDAV, and any
standard WebDAV server.

### 6.1. Configure rclone

```sh
rclone config
# n) New remote
# name> nextcloud
# Storage> webdav
# url> https://cloud.example.com/remote.php/dav/files/you/
# user> you@example.com
# pass> (rclone will obscure it)
```

### 6.2. Add the remote to binpass

```sh
binpass remote add webdav nextcloud nextcloud:password-store
binpass sync --remote=nextcloud
```

### 6.3. Nextcloud-specific

Nextcloud's WebDAV endpoint is at:

```
https://cloud.example.com/remote.php/dav/files/USERNAME/
```

Make sure the `password-store` folder exists (or create it):

```sh
rclone mkdir nextcloud:password-store
```

### 6.4. Important notes

- **No atomicity**: WebDAV PUT replaces the file in place. binpass adds
  verify-after-write (read back and compare) when the transport reports
  `WeakAtomic`.
- **No rename**: WebDAV does not support atomic rename. binpass falls back to
  copy + delete.
- **No history**: WebDAV does not keep old revisions. If you accidentally
  overwrite a file, the old version is gone. For safety, combine with git
  (the store itself is a git repo, and WebDAV is the transport for the files).

---

## 7. Configuration reference

### config.yaml

```yaml
sync:
  # Automatic sync mode. "off" (default) = manual only.
  auto: off

  # Default conflict resolution. "keep-both" (default) = never lose data.
  conflict: keep-both

  # Default remote name. If set, `binpass sync` uses this remote without --remote.
  default_remote: origin

  remotes:
    # Git remote: the store directory IS the git working tree.
    origin:
      type: git
      sign_commits: false

    # Restic remote: encrypted, deduplicated, versioned snapshots.
    s3-backup:
      type: restic
      url: s3:s3.amazonaws.com/my-bucket/binpass
      password_command: "cat /run/secrets/restic-password"

    # Local restic remote: encrypted backups on a mounted disk.
    local-backup:
      type: restic
      url: /mnt/backup/binpass
      password_command: "pass show restic/binpass"

    # S3 remote: uses rclone.
    s3-rclone:
      type: s3
      url: mybucket:password-store

    # Google Drive remote: uses rclone.
    gdrive:
      type: gdrive
      url: gdrive
      folder: binpass-store

    # Yandex.Disk remote: uses rclone.
    yandex:
      type: yandex
      url: yandex
      folder: password-store

    # WebDAV remote: uses rclone.
    nextcloud:
      type: webdav
      url: nextcloud:password-store
```

### Environment variables

| Variable | Effect |
|---|---|
| `BINPASS_STATE_DIR` | Override the sync state directory (default: `$XDG_STATE_HOME/binpass`) |
| `BINPASS_SYNC_AUTO` | Override `sync.auto` |
| `BINPASS_SYNC_CONFLICT` | Override `sync.conflict` |
| `BINPASS_SYNC_DEFAULT_REMOTE` | Override `sync.default_remote` |

### State directory

The sync state database is stored at `$XDG_STATE_HOME/binpass/state.db`
(default `~/.local/state/binpass/state.db`), or wherever `BINPASS_STATE_DIR`
points. This directory is **always outside the password store**. If state.db were inside the store:

1. It would be committed to git, mixing device-specific state with the shared
   store.
2. It would be synced to Google Drive / Yandex, exposing sync metadata.
3. `pass git status` would show noise.

If `binpass fsck` detects state.db inside the store, it reports a critical
error.

---

## 7.5 Syncing a store with a tomb

A closed tomb is one large opaque file where the entries used to be, and
every transport carries it correctly. What differs is the cost.

| Tomb backend | git | restic | rclone (S3, Drive, WebDAV) |
|---|---|---|---|
| `coffin` | fine | best | fine |
| `luks` | avoid | **best** | avoid |
| `sparsebundle` | avoid | **best** | avoid |

git keeps every version of the container in full and encrypted blobs do not
delta-compress, so a 1 GB LUKS image edited daily is a repository growing by
a gigabyte a day. restic deduplicates at block level, which is exactly what a
disk image wants: one changed entry rewrites the blocks that changed rather
than the whole image. binpass prints a warning when it is about to push a
block container somewhere that stores whole copies.

**Close the tomb before syncing, not after.** With it open, the store is a
directory of entries and the transport uploads each one — precisely the
metadata the tomb exists to hide. Worse, the two states interleave badly:
syncing an open tomb and then closing it makes the next sync look like every
entry was deleted at once.

```sh
binpass tomb close
binpass sync
```

See [tomb.md](tomb.md) for the backends themselves.

## 8. Security considerations

### What the provider sees

All cloud providers (Google, Yandex, S3, WebDAV) receive only encrypted
`.gpg` and `.age` files. The provider cannot read your passwords.

**However, entry names are visible** — this is an inherent property of the
pass format. `github.com/alice.gpg` tells the provider you have a GitHub
account for alice. Mitigations:

- **tomb/coffin** (ARCHITECTURE.md §7): the entire store is a single encrypted
  blob. The provider sees one file, not a directory tree.
- **`--obfuscate`** (planned): base32-HMAC path obfuscation. Breaks pass
  compatibility.
- **restic**: the restic transport encrypts everything, including file names
  and directory structure. The provider sees only opaque blobs. This is the
  strongest privacy option for remote storage.

### Conflict files

Conflict files (`.conflict-<device>-<timestamp>.gpg`) are encrypted with the
same recipients as the original entry. The provider sees another encrypted
file — nothing leaks.

### Credential storage

rclone stores OAuth tokens and passwords in `~/.config/rclone/rclone.conf`.
binpass does not store cloud credentials itself — it delegates to rclone
entirely. Secure the rclone config:

```sh
chmod 600 ~/.config/rclone/rclone.conf
```

For production use, consider rclone's [obscured
passwords](https://rclone.org/commands/rclone_obscure/) or environment
variable-based configuration.

### Conditional writes

For git, binpass uses the file's last-modifying commit SHA as the revision
token. A `Put(path, content, expectRev)` call fails if another commit has
touched the file since the SHA was read. This prevents silent overwrites when
two clients push concurrently.

For cloud transports (S3, Drive, Yandex, WebDAV), conditional writes are
best-effort. S3 supports `If-Match` on the ETag (not yet wired). For others,
binpass uses verify-after-write: read the file back after upload and compare.

---

## 9. Troubleshooting

### `sync: no remote configured`

You need either:
- A `.git` directory in the store (git is auto-detected), or
- A `sync.default_remote` in config.yaml, or
- The `--remote=NAME` flag.

### `remote/rclone: rclone not found on PATH`

Install rclone:

```sh
# Nix
nix-env -iA nixpkgs.rclone

# Debian/Ubuntu
curl https://rclone.org/install.sh | sudo bash

# macOS
brew install rclone
```

### `remote/restic: restic not found on PATH`

Install restic:

```sh
# Nix
nix-env -iA nixpkgs.restic

# Debian/Ubuntu
apt install restic

# macOS
brew install restic
```

### `remote/restic: repository not initialised`

binpass auto-initialises restic repos on first use. If this fails, check:

1. The repo path is correct and writable.
2. The password or password_command is correct.
3. For S3/SFTP: credentials and connectivity are working.

```sh
restic cat config --repo s3:s3.amazonaws.com/my-bucket/binpass
```

### `remote/restic: snapshot ... pushed by another client`

Another client pushed a snapshot after you ran `binpass sync` (List) but
before your Push. Re-run `binpass sync` to pull and merge the remote changes.

### `sync: scan local: ...`

The store directory might not exist or be unreadable:

```sh
binpass fsck
```

### Conflicts after every sync

This usually means two devices are editing the same entries independently.
After resolving conflicts once, the next sync should be clean. If it
recurs, check that the state database is not being shared between devices
(`BINPASS_STATE_DIR` must point to a **local** directory, not a network
share).

### Large store is slow on cloud

Initial sync with Google Drive or Yandex involves one API call per file.
For 2,000+ entries, expect 5–10 minutes. Subsequent syncs are faster
because only changed files are transferred.

Pre-warm the remote from a fast connection:

```sh
# One-time bulk upload with rclone directly.
rclone sync ~/.password-store/ gdrive:binpass-store --include "*.gpg" --include "*.age"

# Then let binpass sync handle ongoing deltas.
binpass sync --remote=gdrive
```

### State recovery after crash

If `binpass sync` is interrupted (SIGKILL, power loss, etc.), the state
database recovers automatically on the next run through the write-ahead log.
No manual intervention is needed. Verify with:

```sh
binpass fsck
```
