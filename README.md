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
one-time passwords, and the built-in picker. Sync, tomb, the Secret Service
provider and the plugin system are specified in [ARCHITECTURE.md](ARCHITECTURE.md)
but not yet written.

| Working | Command |
|---|---|
| yes | `init` `ls` `show` `find` `grep` `insert` `edit` `generate` `rm` `mv` `cp` `git` `version` |
| yes | `otp` (pass-otp), `menu` (passmenu / rofi-pass), `generate --words` (diceware) |
| yes | `import` (pass-import, 9 formats), `export` (CSV), `audit` (pass-audit), `binary` (pass-file) |
| not yet | `sync` `tomb` `ss` `plugin` `tui` |

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

That one line is the core of `rofi-pass`. The scripts in [`contrib/`](contrib/)
build on it:

| Script | What it does |
|---|---|
| [`binpass-rofi`](contrib/binpass-rofi) | Two-step rofi menu: pick an entry, then copy / type / autofill / OTP |
| [`binpass-fzf`](contrib/binpass-fzf) | Terminal picker with a preview pane that masks the password |
| [`binpass-dmenu`](contrib/binpass-dmenu) | Minimal passmenu replacement, works on X11 and Wayland |

A complete rofi-pass equivalent, in full:

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
