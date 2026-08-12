# Hiding the whole store: `binpass tomb`

Encrypting each entry hides its contents. It does not hide that
`bank/savings` exists, that you have three accounts at one employer, or that
you created `interviews/competitor` last Tuesday. File names, directory
structure, sizes, and timestamps are all in the clear, and they travel to
whatever you sync with.

`binpass tomb` removes that. When the tomb is closed, the store directory
holds one encrypted blob and nothing else.

```sh
binpass tomb init          # create the container
binpass tomb close         # hide everything
binpass tomb open          # work with the store
```

> Implements [ARCHITECTURE.md](../ARCHITECTURE.md) §7. Code lives in
> `pkg/tomb/`, the command in `internal/cli/tomb.go`.

---

## Contents

1. [Is this for you](#1-is-this-for-you)
2. [Quick start](#2-quick-start)
3. [What each command does](#3-what-each-command-does)
4. [Backends](#4-backends)
5. [Auto-close](#5-auto-close)
6. [Crash recovery](#6-crash-recovery)
7. [Working with sync and git](#7-working-with-sync-and-git)
8. [What is protected, and what is not](#8-what-is-protected-and-what-is-not)
9. [Compared with pass-tomb](#9-compared-with-pass-tomb)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Is this for you

A tomb is worth the friction when the *shape* of your store is sensitive:

* You sync through a provider you do not trust with metadata. Dropbox cannot
  read `bank/savings.age`, but it can see the name, and names are often
  enough.
* Your laptop may be examined — at a border, by an employer, after a theft.
  A closed tomb reveals one opaque file.
* The names themselves are the secret: client names, case numbers, the fact
  that an account exists at all.

It is **not** worth it when:

* You only fear disk theft while powered off — full-disk encryption already
  covers that, with none of the friction.
* You want protection while you are logged in and working. An open tomb is a
  normal directory; see [§8](#8-what-is-protected-and-what-is-not).

A tomb is a metadata-at-rest tool. It answers "what can someone learn from
this disk", not "what can malware do while I am using the machine".

---

## 2. Quick start

```sh
# A store with entries in it already.
binpass ls
# Password Store
# ├── bank
# │   └── savings
# └── github.com
#     └── alice

# Pack it. Nothing is removed yet: init is add-only.
binpass tomb init
# Tomb initialised (coffin) for /home/you/.password-store

# Hide it.
binpass tomb close
# Tomb closed.

ls -a ~/.password-store
# .  ..  .age-recipients  store.coffin.age
```

Everything is now inside `store.coffin.age`. To work with the store again:

```sh
binpass tomb open --timer=1h
# Tomb opened (coffin).
# Auto-closing in 1h0m0s. Press Ctrl-C to close now.
```

**`open` holds the terminal.** That is deliberate — see
[§3.2](#32-binpass-tomb-open). Use a second terminal, or read
[§5.3](#53-running-open-in-the-background).

---

## 3. What each command does

### 3.1 `binpass tomb init`

```
binpass tomb init [--type=coffin|luks|sparsebundle] [--size=1G] [-r age1...]
```

Creates the container from the store as it is now. **Your plaintext is not
touched**: `init` only adds `store.coffin.age` beside it, and the store keeps
working normally until you run `close`.

Recipients come from `.age-recipients` or `.gpg-id` unless you pass `-r`. The
container is encrypted to the same keys as your entries, so a YubiKey that
already unlocks the store unlocks the tomb too — there is no separate tomb
password to remember or lose.

`--size` applies to LUKS and sparsebundle only. Coffin grows with its
contents and ignores it.

### 3.2 `binpass tomb open`

```
binpass tomb open [--timer=30m]
```

Decrypts the archive back into the store directory, then **stays in the
foreground** until you press Ctrl-C or the timer fires.

The process has to stay alive because it *is* the auto-close mechanism: it
holds the timer and the D-Bus subscriptions for screen lock and suspend. A
tomb that opened and forgot about itself would leave your store lying open
after you walked away, which is the one failure this feature exists to
prevent.

On Linux the plaintext goes to tmpfs where available, so it is RAM-backed
rather than written to the disk.

### 3.3 `binpass tomb close`

```
binpass tomb close [--force]
```

Re-encrypts the store into a fresh archive, swaps it in atomically, then
overwrites and removes the plaintext.

```
Tomb closed.
Note: shred on SSD with wear-leveling does not guarantee data destruction.
```

That note is not boilerplate. On an SSD the controller writes to a different
physical block than the one you asked to overwrite, so the old contents can
survive in a block you can no longer address. Overwriting is best-effort on
flash; the honest mitigation is full-disk encryption underneath.

`--force` skips the overwrite pass. It is faster on a large store and worth
it only when the disk is already encrypted.

### 3.4 `binpass tomb status`

```sh
binpass tomb status
```

```
Tomb: open
  backend:  coffin
  store:    /home/you/.password-store
  auto-close: 30m0s timer + D-Bus screen lock/suspend
```

Four states: `open`, `closed`, `not initialised`, and
`stale (crash without close)` — see [§6](#6-crash-recovery).

---

## 4. Backends

| Backend | Platform | Root needed | Status |
|---|---|---|---|
| `coffin` | Linux, macOS, Windows | no | **Working**, the default |
| `luks` | Linux | yes (or polkit) | **Working** |
| `sparsebundle` | macOS | no | **Working** |

### 4.1 Coffin

One age-encrypted tar archive. No root, no kernel features, no filesystem
support — it works anywhere binpass does, including Windows.

Because it is encrypted to ordinary age recipients, hardware tokens work
without any tomb-specific support.

Its weakness is honest and structural: while the tomb is open, plaintext
lives in a directory. tmpfs, `mlock`, and auto-close narrow the window; they
do not remove it.

### 4.2 LUKS

A dm-crypt container, driven through the external `cryptsetup` binary. It
closes the gap coffin cannot: decrypted data exists only in the kernel's
mapping and never lands in a file, so there is no plaintext directory to
shred and no window where one is sitting on disk.

```sh
sudo binpass tomb init --type=luks --size=1G
sudo binpass tomb open
# ... use the store ...
sudo binpass tomb close
```

**`init` moves your entries into the container.** After it finishes, the
store directory holds `store.luks`, `store.luks.key.age`, and your dotfiles;
the entries themselves are inside the container and only appear when it is
mounted.

The container key is random and never typed by you — it is stored in
`store.luks.key.age`, encrypted to the store's own age recipients. Unlocking
the tomb is therefore an ordinary age decryption, and a YubiKey that already
unlocks your entries unlocks the container too. There is no second passphrase
to remember, and the key never touches the disk in the clear: it is handed to
`cryptsetup` on stdin, never as a file and never as an argument.

`--size` is fixed at creation and the file is sparse, so `--size=10G` costs
only what you actually store. The minimum is 16M.

#### Running it without sudo every time

`cryptsetup`, `mount` and `umount` need root. Rather than running all of
binpass as root, grant just those three:

```sh
# /etc/sudoers.d/binpass-tomb   (visudo -f, not an editor)
you ALL=(root) NOPASSWD: /usr/sbin/cryptsetup, /usr/bin/mount, /usr/bin/umount
```

Understand what that grants before you do it: unrestricted `mount` is close
to root itself. On a single-user machine that is often an acceptable trade;
on a shared one it is not, and `sudo binpass tomb open` is the honest answer.

#### Compatibility with pass-tomb

Not compatible. `pass-tomb` uses `tomb(1)`, which has its own container
format and key handling; this is plain LUKS2 with an age-encrypted key file.
Existing tombs are not opened by binpass, and the ARCHITECTURE note claiming
otherwise (§7.1) is aspirational rather than describing this implementation.

### 4.3 Sparsebundle

An encrypted APFS disk image driven through `hdiutil`, on macOS. Like LUKS it
keeps the plaintext in a mounted filesystem rather than a directory that has
to be shredded afterwards; unlike LUKS it needs no root, because macOS lets
an ordinary user attach a disk image.

```sh
binpass tomb init --type=sparsebundle --size=1G
```

The image's passphrase is random, never seen by the user, and stored
age-encrypted beside it — the same arrangement LUKS uses, so a hardware token
that unlocks the store unlocks the image.

See [macos.md](macos.md) for the rest, including what has not been run on a
real Mac.

---

## 5. Auto-close

An open tomb is only as safe as the time it stays open, so closing it is
automatic.

### 5.1 The timer

```sh
binpass tomb open --timer=30m
```

Without `--timer`, there is no timeout: the tomb stays open until you close
it or the machine sleeps. `binpass tomb status` says so plainly
(`auto-close: disabled (no timer set)`) rather than letting you assume you
are covered.

### 5.2 Screen lock and suspend (Linux)

binpass subscribes to GNOME and freedesktop screensavers on the session bus,
and to logind's suspend signal on the system bus. Locking your screen closes
the tomb.

Check what was actually detected:

```sh
binpass doctor
# [tomb] D-Bus: GNOME screensaver, logind suspend
# [tomb] closed (backend: coffin)
```

If it reports `no screensaver detected (timer-only auto-close)`, your desktop
does not expose a screensaver interface binpass understands, and the timer is
your only automatic protection. Set one.

macOS and Windows are timer-only.

### 5.3 Running open in the background

`open` holding the terminal is inconvenient when you want the tomb open for a
work session. Put it in its own unit rather than backgrounding it blindly, so
that closing is still guaranteed:

```ini
# ~/.config/systemd/user/binpass-tomb.service
[Unit]
Description=binpass tomb

[Service]
Type=simple
ExecStart=%h/.local/bin/binpass tomb open --timer=8h
ExecStop=%h/.local/bin/binpass tomb close
Restart=no
```

```sh
systemctl --user start binpass-tomb    # open
systemctl --user stop  binpass-tomb    # close cleanly
```

`ExecStop` matters: it turns a session ending into a clean close instead of a
stale tomb.

---

## 6. Crash recovery

If the process holding an open tomb is killed — `kill -9`, a battery dying,
an OOM kill — the plaintext stays on disk and the state file is left behind.
binpass notices:

```sh
binpass tomb status
# Tomb: stale (crash without close)
#   backend:  coffin
#   store:    /home/you/.password-store
#   opened:   2026-08-10T23:11:32+03:00
```

It is detected by checking whether the recorded PID is still alive, so a
stale tomb is reported as stale rather than quietly treated as open.

The fix is an ordinary close:

```sh
binpass tomb close
# Tomb closed.
```

Your data is not at risk here — everything is still in the store directory,
in the clear. What you have lost is the hiding, until you close it again.

`binpass doctor` reports the same condition, which is why it is worth running
after an unclean shutdown:

```sh
binpass doctor
# [tomb] stale state detected (PID 1405571 is dead, tomb was not closed cleanly)
```

On Windows, PID checks are conservative and stale tombs are not detected
automatically.

---

## 7. Working with sync and git

**Close the tomb before you sync, not after.** The point is that the provider
receives one blob:

```sh
binpass tomb close
binpass sync
```

With the tomb open you would push every entry as a separate file and hand
over exactly the metadata the tomb exists to hide. Worse, the two states
interleave badly: syncing an open tomb and then closing it makes the next
sync look like every entry was deleted at once.

A safe routine:

```sh
binpass tomb open --timer=1h    # terminal 1, stays running
# ... work in terminal 2 ...
# Ctrl-C in terminal 1
binpass sync                     # push the blob
```

### 7.1 Which backend suits which transport

Every combination works — the container is transferred correctly in all of
them. What differs is how much space it costs on the far end.

| | git | restic | rclone (S3, Drive, WebDAV) |
|---|---|---|---|
| **coffin** | fine | best | fine |
| **luks** | avoid | **best** | avoid |
| **sparsebundle** | avoid | **best** | avoid |
| no tomb | best | fine | fine |

The reason is what each transport stores when one file changes:

* **git** keeps every version in full, forever. A 1 GB LUKS image edited
  daily is a repository growing by 1 GB a day, and `git gc` cannot help:
  encrypted blobs do not delta-compress.
* **rclone** stores the current version, plus older ones if the bucket has
  versioning. Better than git, still a full copy per change.
* **restic** deduplicates at block level. Changing one entry inside a 1 GB
  image rewrites the blocks that actually changed — a few hundred kilobytes,
  not a gigabyte. This is what a disk image needs.

binpass says so when it is about to push a block container somewhere that
keeps whole copies:

```
warning: store.luks is a disk image, and origin stores every version of it in full.
  A restic remote deduplicates at the block level and suits this far better;
  see docs/tomb.md for which tomb backend to use with which transport.
```

It is a warning, not a refusal: a 64 MB image on a private server is a
perfectly reasonable arrangement.

A coffin grows with its contents rather than being a fixed-size image, so it
is the pragmatic choice on git. Set expectations with `.gitattributes`:

```
store.coffin.age binary
```

**A sparse bundle only opens on macOS**, and a LUKS container only on Linux.
Both synchronise anywhere, but the second machine has to be able to open what
it received. For a store shared between a Mac and a Linux box, coffin is the
only backend both can open.

---

## 8. What is protected, and what is not

### Protected

While the tomb is **closed**:

* Entry names, folder structure, and how many entries exist.
* File sizes and timestamps, which leak when you last changed what.
* The contents, as always.

Someone who takes the disk, or the provider you sync with, sees
`store.coffin.age` and its size. That is all.

### Not protected

* **While open, it is a normal directory.** Any process running as you can
  read it. A tomb is not a defence against malware in your session.
* **The archive's size** tracks how much you store. It will not tell anyone
  which sites you use, but a 4 KB store and a 4 MB store are visibly
  different, and the size changes when you edit.
* **Shredding on flash is best-effort.** See [§3.3](#33-binpass-tomb-close).
* **Swap.** `mlock` covers small allocations; a large store being packed can
  still reach swap. Encrypted swap is the fix, and it is a system setting,
  not something binpass can do for you.
* **Your key.** The tomb is encrypted to your age recipients. Whoever holds
  the identity opens the tomb — the tomb adds no second factor by itself.
  If you want one, use a hardware-backed identity (§3 of ARCHITECTURE.md).
* **A running `open`.** The plaintext is exposed for as long as that process
  lives. Set a timer.

---

## 9. Compared with pass-tomb

| | `pass-tomb` | `binpass tomb` |
|---|---|---|
| Platform | Linux | Linux, macOS, Windows |
| Needs root | yes | only for `--type=luks` |
| Dependencies | `tomb`, `cryptsetup`, `pinentry` | none for coffin, `cryptsetup` for LUKS |
| Key | separate GPG-encrypted tomb key | your existing store recipients |
| Hardware tokens | via GPG smartcard | any age recipient, including plugins |
| Auto-close | `tomb slam` on demand | timer + screen lock + suspend |
| Crash detection | none | stale state reported by `status`/`doctor` |
| Isolation while open | dm-crypt mapping | dm-crypt with LUKS, tmpfs with coffin |

Both trades are available: coffin gives up dm-crypt's in-kernel isolation for
portability and no root, LUKS takes it back at the cost of being Linux-only
and needing privileges. Either way there is one key to manage rather than
two, because the container key is encrypted to the store's own recipients.

Existing `pass-tomb` containers are **not** readable by binpass: they are
`tomb(1)` volumes with their own format and key handling, while
`--type=luks` creates plain LUKS2.

---

## 10. Troubleshooting

### `tomb: backend not yet implemented`

No backend returns this any more: coffin, LUKS and sparsebundle are all
built. Asking for one the current OS does not have reports that instead —
LUKS is Linux-only and sparsebundle is macOS-only.

### `tomb: cryptsetup not found on PATH`

The LUKS backend needs it:

```sh
sudo apt install cryptsetup-bin e2fsprogs      # Debian, Ubuntu
sudo dnf install cryptsetup e2fsprogs          # Fedora
nix-shell -p cryptsetup e2fsprogs              # Nix
```

### `tomb: this backend requires root or polkit`

`cryptsetup` cannot open `/dev/mapper/control` as an ordinary user. Run the
command with `sudo`, or grant the three binaries it needs — see
[§4.2](#42-luks).

### `tomb: the kernel has no usable dm-crypt (try: modprobe dm_crypt)`

The device mapper is not available. On a normal system `sudo modprobe
dm_crypt` fixes it; inside a container the image must be run with
`--privileged`, and inside a VM the kernel must have dm-crypt at all.

### `tomb: the key file does not unlock this container`

`store.luks.key.age` does not match `store.luks`. Usually one of the two was
restored from a backup without the other; they are a pair and must be copied
together. Without the matching key file the container cannot be opened, by
anyone, including you.

### `tomb init: specify --recipient or initialise the store first`

`init` had nowhere to read recipients from. Usually the store was never
initialised:

```sh
binpass init --age age1...
```

### `tomb: not initialised`

No `store.coffin.age` in the store directory. Run `binpass tomb init`.
If you expected one, check `PASSWORD_STORE_DIR` points where you think.

### `tomb: already open`

Plaintext entries are present. Either the tomb really is open — check
`binpass tomb status` — or a previous run crashed, in which case status will
say `stale` and `binpass tomb close` resolves it.

### `binpass ls` shows only `store.coffin`

The tomb is closed. That is the intended appearance: the archive is the only
entry-shaped file left. Run `binpass tomb open`.

### `tomb: no recipients found`

`init` needs to know who to encrypt to, and found neither `.age-recipients`
nor `.gpg-id`. Either initialise the store first (`binpass init --age
age1...`) or pass `-r age1...` explicitly.

### The tomb did not close when I locked the screen

Check what binpass detected:

```sh
binpass doctor
```

`no screensaver detected (timer-only auto-close)` means your desktop does not
publish a screensaver interface on D-Bus that binpass recognises. Use
`--timer` — it does not depend on the desktop at all.

### Close is slow on a large store

The overwrite pass rewrites every file before deleting it. On an encrypted
disk that work is redundant:

```sh
binpass tomb close --force
```

### I lost the identity that opens the tomb

The archive is encrypted to your age recipients, and there is no recovery
path — that is the property you asked for.

Back up the identity file. To have a second key able to open the tomb, list
both recipients in the store's `.age-recipients` before running `init`, which
uses every recipient in that file:

```sh
printf 'age1primary...\nage1backup...\n' > ~/.password-store/.age-recipients
binpass tomb init
```

`--recipient` takes a single value and overrides the file, so it is the wrong
tool for a backup key.
