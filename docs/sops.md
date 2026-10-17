# Editing sops files: `binpass sops`

NixOS machines keep their secrets in sops-encrypted YAML or JSON that
[sops-nix](https://github.com/Mic92/sops-nix) decrypts at activation. Editing
one today means `sops edit`: the whole document lands in `$EDITOR` as
plaintext, every key visible at once, and a typo in the YAML costs you the
save. `binpass sops` puts the same file behind the binpass TUI and CLI: keys
become entries, nested maps become folders, and each change re-encrypts
only the key it touched.

```sh
binpass sops edit secrets/hosts.yaml           # browse and edit in the TUI
binpass sops ls   secrets/hosts.yaml           # key names, one per line
binpass sops get  secrets/hosts.yaml db/password
binpass sops set  secrets/hosts.yaml db/password   # value from a hidden prompt or stdin
binpass sops rm   secrets/hosts.yaml db/password
```

> Code lives in `pkg/sopsfile/`, the commands in `internal/cli/sops.go`.
> The OpenSpec change that introduced it is `openspec/changes/add-sops-secrets/`.

---

## Contents

1. [What it is and is not](#1-what-it-is-and-is-not)
2. [Prerequisites](#2-prerequisites)
3. [Key addressing](#3-key-addressing)
4. [The commands](#4-the-commands)
5. [The TUI](#5-the-tui)
6. [Values and newlines](#6-values-and-newlines)
7. [Creating a file](#7-creating-a-file)
8. [What binpass never touches](#8-what-binpass-never-touches)
9. [A `make secrets-edit` target](#9-a-make-secrets-edit-target)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. What it is and is not

`binpass sops` is a front end to one sops-encrypted document at a time. It
is not a store backend: nothing in `$PASSWORD_STORE_DIR` changes, there is no
sync, no git integration, no audit of the file, and the file is never copied
anywhere. Each command takes the file as its first argument and leaves it as
sops wrote it.

Every operation is an invocation of the `sops` binary on your `PATH`:

| operation | sops command |
|---|---|
| read | `sops decrypt --output-type json FILE` |
| write a key | `sops set --value-stdin FILE '["a"]["b"]'` |
| delete a key | `sops unset FILE '["a"]["b"]'` |
| create the file | `sops encrypt --filename-override FILE --input-type json` |

binpass never sees a master key, never parses `.sops.yaml`, and never
re-encrypts the data key. `sops set` rewrites just the one value, so the
git diff of a one-key change is one line plus the `lastmodified` and `mac`
fields sops always updates.

## 2. Prerequisites

* `sops` 3.10 or newer on `PATH` (`--value-stdin` appeared in 3.10; older
  versions fail with sops's own usage error). The Nix dev shell ships it;
  the Debian-based test images install the pinned release through
  `scripts/install-sops.sh`.
* Whatever sops needs to decrypt the file: `SOPS_AGE_KEY_FILE`, a key in
  `~/.config/sops/age/keys.txt`, a GPG key, a cloud KMS session. If
  `sops decrypt FILE` works in your shell, `binpass sops` works too.
* For new files, a `.sops.yaml` with a `creation_rules` entry matching the
  path. binpass hands sops the path exactly as you typed it, so write the
  rules for the paths you use.

Supported extensions: `.yaml`, `.yml`, `.json`. Other sops formats (dotenv,
ini, binary) are refused with an error naming the supported ones.

## 3. Key addressing

A nested map is a folder; a key is named by joining its map path with `/`:

```yaml
db:
  password: hunter2
  user: admin
token: abc
```

lists as `db/password`, `db/user`, `token`, and `binpass sops ls FILE db`
lists the first two. This is the same path sops-nix uses for nested secrets
(`sops.secrets."db/password"`), so what you see in binpass is what you
reference in your NixOS config.

Two consequences:

* A key whose own name contains `/` cannot be told apart from a nested
  path. Listing a file with such a key fails and names the key; rename it
  with `sops` itself.
* A key whose name contains `[` cannot be written or deleted: sops's path
  syntax has no escaping. It still lists and reads.

Non-string leaves (numbers, booleans, lists) are shown as their JSON text.
Writing one through binpass stores a string.

## 4. The commands

`binpass sops ls FILE [GROUP]` — key names under GROUP (default: all),
sorted, one per line. A missing file lists nothing.

`binpass sops get FILE KEY` — the value, verbatim, with no newline added.
Pipe it where a token belongs:

```sh
binpass sops get secrets/hosts.yaml github/token | gh auth login --with-token
```

`binpass sops set FILE KEY` — the value is never taken from argv. On a
terminal binpass prompts once without echo; `--multiline` (`-m`) reads
until Ctrl-D instead. From a pipe stdin is read to EOF, so a PEM key needs
no flag:

```sh
binpass sops set secrets/hosts.yaml ssh/host_key < /etc/ssh/ssh_host_ed25519_key
```

Setting a key whose parent is an existing scalar is refused rather than
silently replacing the scalar with a map.

`binpass sops rm FILE KEY` — delete one key. `--recursive` (`-r`) deletes a
group and everything under it; without it a group is refused. Deleting the
last key of a group leaves an empty map in the file, which binpass hides
from listings.

## 5. The TUI

`binpass sops edit FILE` opens the same full-screen browser `binpass tui`
uses, with the file's keys as the tree. Everything in [docs/tui.md](tui.md)
that works on entries works here: fuzzy search, open, edit in the staged
editor, insert, rename, move between folders, duplicate, delete, generate a
password into a key, copy to clipboard, type, grep across values, audit.

Four bindings need the store to be a directory and report
"not available for a single sops file" instead: history (`y`), store status
(`S`), attach (`b`) and extract (`x`).

Every save in the TUI is one `sops set`, applied immediately; there is no
"save file" step and quitting discards nothing. The autolock and the
plaintext-never-on-disk rules apply unchanged.

## 6. Values and newlines

sops-nix writes each value to `/run/secrets/<name>` byte for byte, and many
consumers (`htpasswd`, `wg` keys, API tokens compared in shell) break on a
trailing newline. The pass format, on the other hand, always ends the
password line with one. binpass reconciles the two on write:

* editing an existing key keeps whether the stored value ended with a
  newline;
* a new single-line value is stored without its newline;
* a new multi-line value is stored verbatim.

`get` prints exactly what is stored. If you need a trailing newline on a
single-line secret, set it with `sops set` once; binpass preserves it from
then on.

## 7. Creating a file

Only `set` creates a file. The first key becomes a one-key document that
`sops encrypt` encrypts under the matching `.sops.yaml` creation rule, and
the result is written to a 0600 temporary file next to the target and
renamed over it. `ls` and `get` on a missing file report an empty document;
nothing is created by reading.

Without a matching creation rule sops refuses, and the error says so.

## 8. What binpass never touches

* Master keys, `.sops.yaml`, `sops updatekeys`, key rotation: use sops.
* Comments on keys binpass rewrites: sops keeps comments on untouched
  keys; a rewritten key behaves as it does under `sops set`.
* Anchors, merge keys and other YAML features that do not survive a JSON
  round trip are read through sops's own JSON output, so what binpass lists
  is what sops-nix would decrypt.

## 9. A `make secrets-edit` target

```make
SECRETS ?= secrets/$(shell hostname).yaml

secrets-edit:
	binpass sops edit $(SECRETS)

secrets-set:
	@binpass sops set $(SECRETS) $(KEY)

secrets-ls:
	@binpass sops ls $(SECRETS)
```

`make secrets-edit` opens the host's file; `make secrets-set KEY=db/password`
prompts for one value. Commit the file afterwards as you would after
`sops edit`.

## 10. Troubleshooting

**`sopsfile: sops not on PATH`** — install sops (`nix shell nixpkgs#sops`,
or `scripts/install-sops.sh`).

**`sops decrypt: ... no key could decrypt the data key`** — the environment
cannot decrypt the file. Check `SOPS_AGE_KEY_FILE` or
`~/.config/sops/age/keys.txt`; run `sops decrypt FILE` by hand.

**`sops encrypt: ... no matching creation rules found`** — the path of the
new file matches no rule in `.sops.yaml`. Run from the directory the rules
are written for, or add a rule.

**`sopsfile: key "a/b" contains '/' and cannot be addressed`** — a literal
`/` in a key name collides with path addressing. Rename it with
`sops set`/`sops unset`.

**`Invalid --set value format`** from sops — the sops on `PATH` is older
than 3.10. `sops --version` tells.
