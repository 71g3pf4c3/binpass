# binpass on macOS

Everything in binpass works on macOS except the Secret Service provider,
which is a Linux D-Bus interface with no equivalent to serve. In its place
there is Keychain integration, an encrypted sparse bundle for the tomb, and
auto-close that follows the screen lock.

```sh
brew install age gnupg          # age for the default backend, gnupg for .gpg entries
binpass init --age age1...
binpass tomb init --type=sparsebundle --size=1G
binpass keychain import
```

> Implements [ARCHITECTURE.md](../ARCHITECTURE.md) §6.5 and §7. Code lives in
> `pkg/keychain/` and `pkg/tomb/sparsebundle_darwin.go`.

---

## Contents

1. [What works, and what does not](#1-what-works-and-what-does-not)
2. [Installing](#2-installing)
3. [The clipboard](#3-the-clipboard)
4. [The tomb: sparse bundle](#4-the-tomb-sparse-bundle)
5. [Auto-close and the screen lock](#5-auto-close-and-the-screen-lock)
6. [Keychain integration](#6-keychain-integration)
7. [Hardware keys and Touch ID](#7-hardware-keys-and-touch-id)
8. [Running things at login](#8-running-things-at-login)
9. [What is untested](#9-what-is-untested)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. What works, and what does not

| Feature | On macOS |
|---|---|
| The whole pass command surface | Yes, identically |
| age and GPG backends | Yes |
| `otp`, `audit`, `import`, `export`, `binary` | Yes |
| `sync` — git, restic, rclone | Yes |
| `tui`, `menu`, `history` | Yes; `menu` uses fzf, since rofi is Linux-only |
| Clipboard | Yes, through `pbcopy`/`pbpaste` |
| `tomb --type=coffin` | Yes |
| `tomb --type=sparsebundle` | Yes, encrypted APFS image, no root needed |
| `tomb --type=luks` | No: dm-crypt is a Linux kernel feature |
| Auto-close on screen lock | Yes |
| `keychain import/export` | Yes |
| `ss` — Secret Service provider | No: D-Bus interface, Linux only |

The one real gap is `ss`. macOS has no bus name to take over, so programs
that want the system keystore get the Keychain, and binpass moves secrets in
and out of it rather than pretending to be it.

---

## 2. Installing

```sh
# Homebrew
brew install age            # the default crypto backend
brew install gnupg          # only if you have .gpg entries
brew install fzf            # for binpass menu

# binpass itself
go install github.com/71g3pf4c3/binpass/cmd/binpass@latest
```

With Nix:

```sh
nix profile install github:71g3pf4c3/binpass
```

The nix-darwin module is not written; the home-manager module works on macOS
for everything except the systemd units, which are Linux-only. Use a launchd
agent instead — see [§8](#8-running-things-at-login).

---

## 3. The clipboard

`binpass show -c` copies through `pbcopy` and restores whatever was on the
clipboard before, once the timeout expires:

```sh
binpass show -c github.com/alice
# Copied github.com/alice to clipboard. Will clear in 45 seconds.
```

**Universal Clipboard sends it to your other devices.** If Handoff is on, a
password copied on a Mac is available to every device signed into the same
Apple ID, and binpass cannot clear those. Turn it off for a machine holding
secrets:

> System Settings → General → AirDrop & Handoff → Handoff

---

## 4. The tomb: sparse bundle

The store's own encryption hides what an entry contains; it does not hide
that `bank/savings` exists. `binpass tomb` packs the whole store away when
it is not in use.

macOS has two backends:

| | `coffin` | `sparsebundle` |
|---|---|---|
| Container | one age-encrypted tar archive | encrypted APFS disk image |
| Needs root | no | no |
| While open | a directory on disk | a mounted filesystem |
| Closing | re-encrypt, then overwrite the files | unmount |
| Portable | works on Linux and Windows too | macOS only |

```sh
binpass tomb init --type=sparsebundle --size=1G
binpass tomb close
binpass tomb open --timer=1h
```

**`init` moves your entries inside.** Afterwards the store directory holds
`store.sparsebundle`, `store.sparsebundle.key.age` and your dotfiles; the
entries appear only while the image is attached.

The image's passphrase is random and you never see it. It lives in
`store.sparsebundle.key.age`, encrypted to the store's own age recipients,
so a YubiKey that unlocks your entries unlocks the image too — there is no
second password to remember, and none is written to disk in the clear.

The image is sparse, so `--size=10G` costs only what you actually store. The
minimum is 16M.

### Why prefer it over coffin

Closing a coffin overwrites the plaintext files and deletes them, which on
flash storage is best-effort: the controller may write elsewhere and leave
the old block readable. A sparse bundle never writes plaintext to a file at
all — it is a filesystem the kernel mounts, and closing it is an unmount.

Coffin is still the better choice if the store is synchronised to a machine
that is not a Mac: a sparse bundle can only be opened on macOS.

---

## 5. Auto-close and the screen lock

An open tomb is only as safe as the time it stays open.

```sh
binpass tomb open --timer=30m
```

The tomb also closes when you lock the screen. binpass reads the lock state
from the window server through `ioreg`, checking every two seconds.

The polling is deliberate. The notification API is Objective-C, and reaching
it means CGO, which would cost the statically linked universal binary — a
two-second delay is the smaller price. Only a transition into the locked
state closes the tomb, so opening one over SSH while the screen is already
locked does not immediately close it again.

Check what binpass sees:

```sh
binpass doctor
# [tomb] screen lock: detected through the window server (currently unlocked)
```

Suspend is **not** a separate trigger on macOS: closing the lid locks the
screen, which is the trigger, so the effect is the same.

---

## 6. Keychain integration

The Keychain cannot be replaced, so binpass moves secrets in and out of it.

### Seeing what is there

```sh
binpass keychain list
# github.com	alice
# gitlab.com	bob
# imap.example.com	alice@example.com
```

This reads names only. No secret is decrypted and nothing prompts.

### Importing

```sh
binpass keychain import --dry-run       # what would happen, no prompts
binpass keychain import                 # everything
binpass keychain import github.com      # one service
binpass keychain import --force         # overwrite existing entries
```

Items land under `keychain/<service>/<account>`:

```
hunter2
username: alice
keychain-service: github.com
label: GitHub
```

**macOS prompts once per item**, because reading a Keychain secret is a
privileged operation and the prompt comes from the system, not from binpass.
Importing a large Keychain means a lot of clicking. `--dry-run` first is
worth the minute it takes.

Click "Always Allow" and macOS stops asking for that item — for binpass
specifically, since the grant is per program.

Dismissing a prompt skips that one item and the import continues.

### Exporting

```sh
binpass keychain export github.com/alice
binpass keychain export github.com/alice --service=github.com --account=alice
```

Useful for a program that reads only the Keychain: keep the entry in the
store, and put a copy where that program will find it. The service defaults
to the entry name and the account to the entry's `username` field.

The copy does **not** stay in step. Changing the entry afterwards means
exporting it again.

---

## 7. Hardware keys and Touch ID

A YubiKey works the same as on Linux, through the age plugin protocol:

```sh
brew install age-plugin-yubikey
age-plugin-yubikey                       # generate an identity on the key
binpass init --age age1yubikey1...
```

Every decryption then needs a touch, including opening a tomb, because the
tomb's key is an ordinary age recipient.

**Touch ID as a store unlock factor is not implemented.** ARCHITECTURE.md
§6.5 describes wrapping the age identity in a Keychain item guarded by
`kSecAccessControlUserPresence`, which would let a fingerprint stand in for a
token. Reaching that API means the Security framework, which means CGO, and
the trade has not been made. A YubiKey covers the same ground today and works
on every OS.

---

## 8. Running things at login

There is no systemd on macOS. For a tomb that opens at login and closes
cleanly at logout, use a launchd agent.

`~/Library/LaunchAgents/dev.binpass.tomb.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>dev.binpass.tomb</string>
  <key>ProgramArguments</key>
  <array>
    <string>/opt/homebrew/bin/binpass</string>
    <string>tomb</string>
    <string>open</string>
    <string>--timer=8h</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PASSWORD_STORE_DIR</key>
    <string>/Users/you/.password-store</string>
    <key>BINPASS_IDENTITY</key>
    <string>/Users/you/.local/share/binpass/identities.age</string>
  </dict>
</dict>
</plist>
```

```sh
launchctl load ~/Library/LaunchAgents/dev.binpass.tomb.plist
launchctl unload ~/Library/LaunchAgents/dev.binpass.tomb.plist
```

launchd has no equivalent of systemd's `ExecStop`, so unloading the agent
kills the process without closing the tomb. Close it explicitly:

```sh
binpass tomb close
```

Or rely on the timer and the screen lock, which do not depend on the agent
being stopped politely.

---

## 9. What is untested

Stated plainly, because it affects how much to trust this.

The macOS-specific code — the sparse bundle backend, the screen lock watcher,
and the Keychain integration — **has never been run on a Mac**. It was
written and tested on Linux.

What that does and does not mean:

* **Tested anywhere:** the command arguments passed to `hdiutil` and
  `security`, their error classification, the `ioreg` output parser, the
  Keychain dump parser including its hex and `<NULL>` forms, path
  sanitisation, and the backend logic driven through a faked command runner.
  These are ordinary functions with ordinary tests, and they are where the
  mistakes usually are.
* **Not verified:** that `hdiutil` and `security` behave as documented, that
  their output matches the samples the parsers were written against, and that
  the integration tests pass — they skip when the tools are absent.

If you run this on a Mac and something does not work, that is a genuine
report rather than a surprise. The integration tests are there and will run
the moment they meet a real system:

```sh
go test ./pkg/tomb/ -run TestBundleAgainstRealHdiutil -v
go test ./pkg/keychain/ -v
```

---

## 10. Troubleshooting

### `tomb: hdiutil not found`

hdiutil ships with macOS, so this means the command is not on `PATH` — most
likely a stripped-down environment such as a CI runner.

### `tomb: the stored passphrase does not open this bundle`

`store.sparsebundle` and `store.sparsebundle.key.age` are a pair. Restoring
one from a backup without the other leaves an image nobody can open,
including you. Copy them together.

### `tomb: the bundle is in use`

Something is reading the mounted store — a Finder window, Spotlight
indexing, an editor with a file open. Close it, or force the unmount:

```sh
binpass tomb close --force
```

### The tomb did not close when I locked the screen

Check what binpass detects:

```sh
binpass doctor
```

The lock state is read from the window server, and an unreadable answer is
treated as unlocked deliberately: a tomb that closed because `ioreg` was
killed mid-write would lose a working session at random. Set `--timer` as
well; it does not depend on the window server at all.

### `keychain: the keychain needs a prompt, and none can be shown`

The login keychain is locked, or the command is running somewhere that
cannot show a dialog, such as over SSH:

```sh
security unlock-keychain
```

### `keychain: the prompt was dismissed`

macOS asked and the answer was no. Import skips that item and continues;
running it again asks afresh.

### `binpass menu` finds no picker

rofi and dmenu are Linux-only. Install fzf:

```sh
brew install fzf
```

### GPG entries prompt in a terminal rather than a window

`pinentry-mac` puts the passphrase prompt in a proper dialog:

```sh
brew install pinentry-mac
echo "pinentry-program $(brew --prefix)/bin/pinentry-mac" >> ~/.gnupg/gpg-agent.conf
gpgconf --kill gpg-agent
```
