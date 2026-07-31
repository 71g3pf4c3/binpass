# binpass

A drop-in replacement for [`pass`](https://www.passwordstore.org/) /
[`gopass`](https://www.gopass.pw/) that encrypts with **age** instead of GPG,
with built-in **TOTP/HOTP**, typed secrets (login, text, binary, bank cards),
and end-to-end-encrypted **synchronisation** across devices.

- Same store layout and command surface as `pass` — existing scripts,
  `passmenu`/`rofi-pass`, and muscle memory keep working.
- Encryption with `age` (X25519, ssh keys, passphrase, YubiKey/FIDO2 plugins).
- One binary, no CGO, cross-platform (Linux, macOS, Windows).

> The synchronisation **server** (`binpassd`) lives on the [`server`](../../tree/server)
> branch. This branch is the client and its local/offline sync engine.

---

## Install

```sh
git clone https://github.com/71g3pf4c3/binpass && cd binpass
make build           # -> bin/binpass  (or: CGO_ENABLED=0 go build ./cmd/binpass)
```

Check the build metadata (required by the spec):

```sh
binpass version
# binpass v0.1.0
# commit: abc1234
# built:  2026-07-31T…Z
# go:     go1.26 · os/arch: linux/amd64
```

---

## Quick start

```sh
# 1. Create a store and a new age key in one step.
binpass init --generate-identity
#   generated identity: ~/.config/binpass/identities.age
#   recipient:          age1…

# 2. Add secrets (first line is the password, pass convention).
binpass insert github.com/alice           # prompts, hidden input
binpass generate github.com/bob 25        # random 25-char password
printf 'hunter2\nurl: https://x\n' | binpass insert -m notes/x   # multiline

# 3. Read them back.
binpass                       # list the whole tree
binpass github.com/alice      # show a secret (bare name, like pass)
binpass -c github.com/alice   # copy the password to the clipboard
binpass -c2 github.com/alice  # copy line 2 (e.g. a username field)
```

If you already use `pass`, point binpass at the same store and it just works:

```sh
export PASSWORD_STORE_DIR=~/.password-store   # honoured, plus BINPASS_STORE_DIR
binpass ls
```

---

## Command reference (pass-compatible)

| Command | Description |
|---|---|
| `binpass [ls] [subfolder]` | List the tree (or a subfolder). Bare `binpass` lists everything. |
| `binpass [show] [-c[N]] [--qr[=N]] [--field=k] name` | Show a secret; `-c` copies line N (default 1); `--qr` renders a QR. |
| `binpass name` | Shorthand for `show name`. |
| `binpass insert [-e\|-m] [-f] name` | Add a secret (`-e` echo, `-m` multiline, `-f` force). |
| `binpass generate [-n] [-c] [-i\|-f] name [len]` | Generate a password (default length 25, `-n` no symbols). |
| `binpass edit name` | Edit in `$EDITOR` via a tmpfs file. |
| `binpass rm [-r] [-f] name` | Remove a secret or, with `-r`, a directory. |
| `binpass mv [-f] src dst` / `binpass cp [-f] src dst` | Move/copy, re-encrypting to the destination recipients. |
| `binpass find term…` | List secrets whose name matches any term (tree output). |
| `binpass grep pattern` | Search decrypted contents. |
| `binpass init [-p subfolder] recipient…` | Initialise a store or subfolder; re-encrypts on change. |
| `binpass completion bash\|zsh\|fish\|powershell` | Shell completion. |
| `binpass version` | Version, commit, build date, toolchain. |

### Beyond pass

| Command | Description |
|---|---|
| `binpass otp name` / `binpass otp --watch name` | TOTP/HOTP code from an `otpauth://` URI (pass-otp compatible). |
| `binpass otp append name uri` | Attach an `otpauth://` URI to a secret. |
| `binpass card add\|show name` | Typed bank-card secret (number/holder/expiry/CVV). |
| `binpass recipients add\|remove\|list` · `binpass reencrypt` | Manage age recipients. |
| `binpass sync [--path DIR]` | Synchronise with a remote (see below). |

Any `X-*` header inside a secret is free-form metadata (site, person, bank,
one-time codes…), available on every secret type.

### Environment variables

binpass honours its own `BINPASS_*` variables and the classic `PASSWORD_STORE_*`
aliases so existing tooling keeps working:

```
BINPASS_STORE_DIR            / PASSWORD_STORE_DIR
BINPASS_CLIP_TIME            / PASSWORD_STORE_CLIP_TIME          (seconds)
BINPASS_GENERATED_LENGTH     / PASSWORD_STORE_GENERATED_LENGTH
```

Configuration file: `~/.config/binpass/config.yaml`
(precedence: **flags > env > file > defaults**).

---

## Secret format

The first line is the password (pass rule); the rest is `key: value` fields,
`otpauth://` URIs, or a typed header block:

```
hunter2
otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&period=30
url: https://github.com
username: alice
```

Typed card:

```
BINPASS-SECRET-1.0
Type: card
Bank: Тинькофф
Number: 5536 9138 XXXX XXXX
Holder: ALICE IVANOVA
Expires: 09/29
CVV: 123
X-Meta-Note: primary salary card
```

`Type` is one of `login` (default) · `text` · `binary` · `card` · `otp`.

---

## Synchronisation

Every backend implements one `Remote` interface, driven by a single sync
engine (content-addressed objects + a signed, version-vectored manifest). This
branch ships the **directory remote** — a shared folder, USB drive, or any
cloud-mounted path (Dropbox/Drive/Syncthing):

```sh
# Device A
binpass sync --path /mnt/shared/vault        # pushes objects + commits manifest

# Device B (same age identity + recipients = same owner)
binpass sync --path /mnt/shared/vault        # pulls everything
```

Or set it once in `~/.config/binpass/config.yaml`:

```yaml
sync:
  fs_path: /mnt/shared/vault
```

then just `binpass sync`.

### How conflicts are handled

Nothing is ever lost. Concurrent edits are detected via per-entry version
vectors; the remote side keeps the canonical path and **your local version is
saved as a sibling**:

```
$ binpass sync
synced with fs: pushed 1, pulled 1, generation 4
1 conflict(s):
  github.com/alice (concurrent-edit) — local copy kept as sibling

$ binpass ls
github.com/alice
github.com/alice.conflict-dev-abcd1234-20260731T091819
```

The manifest is signed with the store's Ed25519 key, so a malicious remote can
neither substitute ciphertext nor roll the store back to an older state.
HOTP counters merge automatically as `max()`.

### Server backend

To sync through the authenticated, multi-device **binpassd** server (gRPC +
REST + Swagger, PostgreSQL, E2E-encrypted), see the [`server`](../../tree/server)
branch and its `server/README.md`.

---

## Security model (client)

- Data is encrypted to age recipients; the store holds only ciphertext.
- Sharing a store between your devices = add each device's `age1…` recipient
  and `binpass reencrypt`.
- Local writes are atomic (`tmp → fsync → rename`), `0600`/`0700`.
- Clipboard is cleared after a timeout; passwords are read from the TTY, never
  passed as arguments.

Out of scope: a compromised client OS, keyloggers, or a recipient who was once
granted access (revocation requires `reencrypt` + key rotation).

---

## Development & testing

```sh
make test        # unit tests
make cover       # coverage summary
go test ./...    # everything, incl. e2e (testscript) and integration
go test ./pkg/sync/ -run xxx -fuzz FuzzMerge3NoDataLoss   # fuzzing
```

The suite includes:

- **Unit** tests (table-driven) for `secret`, `otp`, `crypto`, `manifest`,
  version vectors, `merge3`, WAL, `pwgen`, config.
- **Mock-based** tests (`go.uber.org/mock`) for the sync engine against the
  `Remote` interface — including CAS-conflict retry.
- **Integration** tests: two clients synchronising through a real directory
  remote, covering push/pull, concurrent-edit conflicts, and deletions.
- **End-to-end** CLI tests (`rogpeppe/go-internal/testscript`,
  `internal/cli/e2e/testdata/*.txtar`).
- **Fuzzing** for the secret parser, canonical manifest encoding, version-vector
  comparison, and the three-way merge (invariant: no data loss, deterministic).

Layout:

```
cmd/binpass/           CLI entry point (+ ldflags version/commit/date)
internal/cli/          cobra commands (1:1 with pass/gopass), e2e scripts
internal/config/       viper config (YAML + ENV + flags, pass aliases)
pkg/secret/            secret format parser/serialiser
pkg/otp/               TOTP/HOTP (RFC 6238 / 4226)
pkg/crypto/            age encryption (+ generated mocks)
pkg/identity/          age identity loading/generation
pkg/storage/           atomic on-disk tree, hierarchical recipients
pkg/store/             high-level facade (get/set/list/move/reencrypt)
pkg/pwgen/             CSPRNG password generation
pkg/manifest/          manifest, version vectors, canonical JSON, Ed25519 sign
pkg/remote/            Remote interface (+ mocks) + fsremote directory backend
pkg/sync/              merge3, conflict resolution, WAL, sync engine (+ mocks)
pkg/syncadapter/       bridges the store to the sync engine
```
