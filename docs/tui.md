# The binpass TUI

`binpass tui` is a persistent full-screen session for the store: browse,
search, edit, generate, attach, audit — without leaving the terminal, and
without a command per action. It is the tree view of `binpass ls`, the
entry view of `binpass show` and the editor of `binpass insert`, held
together by one key map.

```sh
binpass tui
```

> Implements [ARCHITECTURE.md](../ARCHITECTURE.md) §5 (the `pass-grid`/TUI
> row) and §9. Code lives in `internal/tui/`, the command in
> `internal/cli/tui.go`.

---

## Contents

1. [Sessions, screens and the autolock](#1-sessions-screens-and-the-autolock)
2. [The tree](#2-the-tree)
3. [Opening an entry](#3-opening-an-entry)
4. [Copy, type, fields](#4-copy-type-fields)
5. [Editing an entry](#5-editing-an-entry)
6. [New entries](#6-new-entries)
7. [Generating over an entry](#7-generating-over-an-entry)
8. [OTP: TOTP countdown and HOTP reveal](#8-otp-totp-countdown-and-hotp-reveal)
9. [Binary attachments](#9-binary-attachments)
10. [Grep across contents](#10-grep-across-contents)
11. [The audit report](#11-the-audit-report)
12. [Store status](#12-store-status)
13. [History, duplicate, rename, delete](#13-history-duplicate-rename-delete)
14. [Themes](#14-themes)
15. [Key map](#15-key-map)

---

## 1. Sessions, screens and the autolock

The TUI runs on the alternate screen buffer, so nothing it displayed
survives in your terminal's scrollback — a revealed password does not end
up in a screenshot of last week's buffer. It refuses to start under
`TERM=dumb`, because a terminal that cannot clear a screen cannot keep
secrets off one.

After five minutes of inactivity the session locks: the decrypted entry,
any staged editor copy and the live OTP code are cleared from memory, and
any key returns you to the tree — with nothing open, because what was
open is gone. Opening the entry again means decrypting it again, which on
a hardware token means touching it again. That is the point.

The mouse wheel scrolls the tree, search results, history and the file
picker, three rows at a time. Everything else is keys.

## 2. The tree

```
▾ bank/
  savings
▾ github.com/
  alice
binpass     q:quit  /:search  n:new  b:attach  d:delete  F:grep  A:audit  S:status  enter:open  h:collapse  E:expand-all  C:collapse-all  j/k:nav
```

Directories start expanded one level deep; you open the rest yourself
with `enter` or `l`, and close them with `h`. `E` and `C` expand and
collapse everything under the cursor. Navigation is `j`/`k`, arrows, page
keys, `G` to jump to the bottom, `g` to the top.

`/` opens the search: a case-insensitive fuzzy filter over entry names
that narrows as you type — contiguous matches rank above scattered ones,
an exact prefix above both. `enter` opens the selection, `esc` returns to
the tree. Search never decrypts anything; it works on names only.

Nothing in the tree view touches the store's contents. Deleting needs
`d` plus a confirmation that defaults to *No*, and works on directories
too, with the confirmation saying so.

## 3. Opening an entry

```
▸ github.com/alice
  pass: ••••••••
  url: https://github.com
  username: alice
binpass               p:toggle  e:edit  c:copy  C:field  t:type  o:otp  Y:duplicate  d:delete  r:rename  g:generate  y:history  esc:back
```

Decryption happens in the background, so a hardware-token touch does not
freeze the interface — the view shows `decrypting...` until the entry
arrives, and a failed decryption is reported in place rather than kicking
you back to the tree.

The password is masked by default, and the mask is a fixed eight bullets
regardless of the password's actual length, because a mask that grew with
the secret would leak its length. `p` reveals and re-hides it. `key:
value` lines render as fields, `otpauth://` URIs render as the OTP line,
and everything else renders as the free text it is.

## 4. Copy, type, fields

`c` copies the password; `C` opens a picker of everything copyable in
the entry — the password, every named field, and the live OTP code — and
copies the chosen row. Both go through the same clipboard path as the
CLI's `--clip`, timeout and restore-the-previous-contents included, so
the TUI never clobbers something you copied in the meantime.

`t` types the password into the focused window, the equivalent of
`binpass type` ([docs/typing.md](typing.md)): the text is fed to the
typing tool on standard input, never as an argument, so ps(1) never sees
it. The TUI's own terminal has focus when you press `t`, so it waits
three seconds — switch to the target window — then types with the same
session-based tool selection (`wtype` on Wayland, `xdotool` on X11,
`ydotool` otherwise) that the CLI commands use.

## 5. Editing an entry

`e` opens the editor on the decrypted entry. Changes are **staged**: you
edit a plaintext copy in memory, and nothing touches the store until you
save. The editor models the entry exactly the way pass stores it — a
password line plus an ordered list of body lines — so unchanged lines keep
their position and the saved entry round-trips byte for byte.

The rows are the entry's structure: the password at the top, then every
`key: value` field and every free-form line in order, `otpauth://` URIs
included and labelled. On any row:

| Key | Action |
|---|---|
| `enter` or `e` | edit the row's value (or the password) |
| `K` | rename a field's key — validated against the parser's rules, so a line cannot silently stop being a field |
| `x` or `d` | delete the row |
| `a` | add a `key: value` field |
| `A` | add a free-form note line |
| `p` | toggle the password mask |
| `S` or `ctrl+s` | save |

Saving is gated by what the save would destroy. Editing values and adding
rows never lose bytes, so they apply without a prompt. Replacing the
password or deleting lines is destructive, and the confirmation says so —
`save (overwrites password or deletes lines)` — defaulting to *No*.
Leaving with unsaved changes asks before discarding them, and declining
returns to the editor with the staged copy intact. A failed write (a
read-only store, a full disk) also keeps the editor open, so nothing you
typed is lost to a refusal.

## 6. New entries

`n` from the tree creates an entry in two steps. First the name; the
name must be new — an existing one is refused rather than overwritten.
Then the password: generated by default, with `r` to regenerate, `+`/`-`
to change the length (4 to 128), `s` to drop symbols from the alphabet —
or `ctrl+g` to switch to typing it by hand, in which case every printable
key belongs to the password and regeneration is out.

`enter` creates the entry immediately — the same contract `insert`
gives — and then opens the editor from §5, so fields and notes can be
added before you move on. The entry exists on disk the moment you confirm
the password, with or without the follow-up edits.

## 7. Generating over an entry

`g` from the detail view replaces an existing entry's password: a live
preview, `r` to regenerate, `+`/`-` for length, `s` for the symbol
alphabet — the same generator and the same configured charsets as
`binpass generate`, so a password born in the TUI obeys the same policy
as one from the command line. `enter` applies it, `esc` leaves the old
password untouched.

## 8. OTP: TOTP countdown and HOTP reveal

An entry with an `otpauth://` URI gets an OTP line in the detail view.
TOTP shows the current code with a countdown that ticks every second;
`o` copies it. HOTP shows no code — HOTP codes do not exist until asked
for — and `o` *reveals* one: computes the code, writes the advanced
counter back to the store, then copies. The counter is persisted before
the code is used, because a code from a counter that was never written
is one the server will never accept again.

The TUI, the `otp` command and `otp menu` all run this same sequence, so
all three agree on which code is current no matter which one you used
last.

## 9. Binary attachments

`b` attaches a file: the picker browses the local filesystem — starting
at your home directory the first time, and remembering where you last
browsed after that — directories only, dot-entries hidden, never reading
a file's contents — and the chosen file is encrypted into the store as a
`.b64` entry, the gopass convention, through the same path as
`binpass binary copy`. Opening it from an entry proposes
`<entry>.b64` as the name, so attaching to `bank/card` naturally produces
`bank/card.b64`. Overwriting an existing entry asks first.

A `.b64` entry opens to metadata, never the base64: decoded size and
SHA-256, computed streaming. Editing, generating over, or copying a
base64 blob is refused rather than silently mangled; what works is
`x` to extract, `b` to attach another, and the usual delete, rename and
history.

`x` extracts: pick a destination directory, `S` to choose it, and the
entry is decoded to a 0600 file that is **never overwritten** — an
existing file at the destination aborts the extraction rather than
clobbering data you cannot see from the TUI, and a failed extraction
leaves no half-written file behind.

## 10. Grep across contents

`F` searches the decrypted contents of the whole store — the same
operation as `binpass grep`, regexp semantics included. It runs once,
when you press `enter`, never per keystroke: decrypting the store is
expensive and touch-y, and it happens off the UI loop. Results show each
matching entry with its match count and a preview of the first matching
line; `enter` opens the entry, `h` refines the query, `esc` returns.

The view says what it is about to do before it does it: *decrypts the
whole store — enter to run*.

## 11. The audit report

`A` runs the full store audit — the same engine as `binpass audit`:
zxcvbn strength, reuse, expiry, HIBP k-anonymity with the on-disk cache,
so consecutive audits over an unchanged store stay offline. It decrypts
everything, so it also runs off the UI loop, under a generous timeout.

The report shows the stats line first — audited, critical, warning,
info, clean — then one row per entry with findings, each reduced to its
worst severity, with the first finding as a preview. Critical rows are
coloured as errors. `enter` opens the finding's entry; fixing it is
between you and the editor from §5.

## 12. Store status

`S` shows the store at a glance: the store's path, the entry count, the
git HEAD and the working-tree state (up to eight uncommitted changes,
then an ellipsis), and the time of the last sync. It is read-only
throughout — gathering status never commits, pushes or mutates anything,
and a sync lock held by a running sync shows up as *state unavailable*
rather than a hung TUI.

## 13. History, duplicate, rename, delete

`y` shows the git history of the open entry — commit, date, subject —
read from metadata only, decrypting nothing, so no password can be
revealed by it. Not a git repository, or the entry not tracked yet, says
exactly that.

`Y` duplicates the entry, proposing `<name> (copy)` the way a file
manager would, and keeps appending `(copy)` until the name is free.
Overwriting an existing entry asks first. The copy goes through the same
store path as `binpass cp`.

`r` renames the entry inline; `d` deletes it — or, from the tree, the
selected directory and everything under it — after a confirmation that
defaults to *No* and names the target.

## 14. Themes

The TUI follows your terminal's own palette by default. To dress it in a
named one:

```sh
binpass tui --theme=gruvbox
```

Five ship: `default`, `gruvbox`, `gruvbox-light`, `nord`, `dracula`. The
same choice persists in the config file:

```yaml
# ~/.config/binpass/config.yaml
ui:
  theme: gruvbox
```

`BINPASS_THEME=gruvbox` covers the environment, and `NO_COLOR` still wins
over all of them — a theme chooses colours, never whether to emit them.
Themes colour the TUI only; command output stays byte-identical to pass,
so scripts and the golden compatibility suite never see a difference. A
theme assumes the matching terminal background: gruvbox colours on a
stock black terminal work, but they look right on a gruvbox one. On
Nix / home-manager the theme is an option, so a typo fails at evaluation
rather than at startup:

```nix
programs.binpass.theme = "gruvbox";
```

## 15. Key map

Grouped by view, as the TUI dispatches them:

| View | Key | Action |
|---|---|---|
| tree | `j`/`k`, arrows, page keys | move |
| | `g` / `G` | top / bottom |
| | `enter`, `l` | open entry / expand directory |
| | `h` | collapse |
| | `E` / `C` | expand all / collapse all |
| | `/` | search names |
| | `n` | new entry |
| | `b` | attach a file |
| | `d` | delete entry or directory |
| | `F` | grep contents |
| | `A` | audit |
| | `S` | store status |
| | `q` | quit |
| detail | `p` | reveal / mask the password |
| | `c` / `C` | copy password / pick a field |
| | `t` | type into the focused window |
| | `o` | copy OTP (TOTP) / reveal it (HOTP) |
| | `e` | edit |
| | `g` | generate a new password |
| | `y` | history |
| | `Y` | duplicate |
| | `r` | rename |
| | `d` | delete |
| | `b` | attach |
| | `esc` | back to the tree |
| binary detail | `x` | extract |
| edit | `enter`, `e` | edit value |
| | `K` | rename field key |
| | `a` / `A` | add field / add note |
| | `x`, `d` | delete row |
| | `S`, `ctrl+s` | save |
| | `p` | toggle mask |
| | `esc` | back (confirms if unsaved) |
| insert | `ctrl+g` | toggle generator / manual password |
| generate | `r`, `+`, `-`, `s` | regenerate, length, symbols |
| files | `enter`, `l` | open |
| | `h` | parent directory |
| | `S` | choose this directory (extract) |
| grep | `h` | refine the query |
| history, status, audit | `esc` | back |

Confirmations everywhere default to *No* and answer to `enter` and `esc`.
