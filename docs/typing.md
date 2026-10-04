# Typing secrets into windows

Some forms refuse a paste. Some lock the clipboard. And a one-time password
loses seconds of its validity while you move it through one. `binpass type`
decrypts an entry and sends it as keystrokes to whatever window has focus,
without the clipboard ever being involved.

```sh
binpass type github.com/alice
```

> Code lives in `pkg/typer/`; the commands in `internal/cli/type.go`,
> `internal/cli/menu.go` and `internal/cli/otp.go`.

---

## Contents

1. [The three tools, and how one is picked](#1-the-three-tools-and-how-one-is-picked)
2. [Forcing a tool](#2-forcing-a-tool)
3. [What gets typed](#3-what-gets-typed)
4. [`menu --type` and `otp menu`](#4-menu---type-and-otp-menu)
5. [The security model, stated plainly](#5-the-security-model-stated-plainly)
6. [What the Nix package ships](#6-what-the-nix-package-ships)
7. [When typing is the wrong tool](#7-when-typing-is-the-wrong-tool)

---

## 1. The three tools, and how one is picked

Three backends exist, and all three read the text from standard input when
given `-` as their file argument:

| Tool | Session it assumes | How binpass decides |
|---|---|---|
| `wtype` | Wayland | `WAYLAND_DISPLAY` set and `wtype` on `PATH` |
| `xdotool` | X11 | `DISPLAY` set and `xdotool` on `PATH` |
| `ydotool` | either, via uinput | the last resort — no session variable can vouch for it |

Autodetection walks that table in order and runs the first tool this session
can use. `ydotool` runs last on purpose: it speaks to the kernel's uinput
interface through `ydotoold`, a daemon whose presence `LookPath` cannot
confirm, so a stock `ydotool` on `PATH` proves nothing about whether it will
work.

When nothing qualifies, you get one error naming the fix:

```
typer: no typing tool found; install wtype, ydotool or xdotool
```

A tool that starts and then fails is the end of the attempt — binpass does
not cascade to the next candidate. A half-typed password from a broken tool
followed by a full retry from another one would corrupt whatever field
received both.

## 2. Forcing a tool

Autodetection trusts the session variables, and sessions lie: a launcher
started before the compositor can lack `WAYLAND_DISPLAY` on a Wayland
desktop, just as an SSH login can inherit a stale `DISPLAY`. So every
command that types accepts an override:

```sh
binpass type --tool=wtype github.com/alice
binpass menu --type --tool=xdotool
binpass otp menu --tool=ydotool
```

An explicit `--tool` is deliberately **not** gated by the session variables
— the tool's own failure is the honest answer when the environment was
wrong. Presence on `PATH` is still checked, so a missing binary is reported
in binpass's words rather than the exec package's.

`auto` is the default. Forcing `--tool=auto` also counts as a choice: it
cancels the configured setting and returns to detection, so the flag can
always undo the config.

The same choice can be made once for every invocation:

```sh
# ~/.config/binpass/config.yaml
typer:
  tool: wtype
```

`BINPASS_TYPER_TOOL=wtype` covers the environment. Precedence is
`--tool` > `BINPASS_TYPER_TOOL` > `typer.tool` > autodetection.

The two configured sources fail differently, on purpose. A bad value in
the config file is a load error — the file is written deliberately, so a
typo there should stop you at startup. A bad value in the environment
variable is deliberately *not* validated: a typo in a shell profile must
not break every binpass invocation from that shell, only the commands that
actually type.

An unknown name is rejected with the valid list, before the store is
touched:

```
typer: unknown tool "wtypo"; valid: auto, wtype, xdotool, ydotool
```

The name is validated up front, before the store is decrypted and the
picker is drawn — a typo should fail fast, not after the secret has been
read.

## 3. What gets typed

`--field` selects the value, exactly as `show --field` and `menu --field`
do:

```sh
binpass type github.com/alice                    # the password (default)
binpass type --field=username github.com/alice  # a named field
binpass type --field=all github.com/alice       # the whole entry
binpass type --field=otp github.com/alice       # the current one-time password
```

`otp` is the one field that is not stored but computed, and it shares its
code path with the `otp` command: an HOTP counter is advanced and persisted
at the same moment it would be from `binpass otp`, so the two commands can
never disagree about which code is current.

`--delay` waits before the first keystroke lands:

```sh
bindsym $mod+Shift+p exec binpass type --delay=300ms github.com/alice
```

A hotkey-driven invocation often needs a beat for focus to settle on the
target window; without the delay the head of the secret lands in whatever
still had focus, and a form that already received three characters of your
password will happily keep them.

## 4. `menu --type` and `otp menu`

`binpass menu` picks an entry and then copies, prints or types it.
`--type` chooses typing:

```sh
binpass menu --type                     # pick, then type the password
binpass menu --type --field=otp         # pick, then type its one-time code
binpass otp menu                        # the same, specialised: typing is the default
```

`otp menu` exists because typing is the whole point of a one-time password
— by the time you have pasted it, seconds of its validity are gone. It
types by default; `--print` and `--copy` are the opt-outs. It takes the
same `--launcher`, `--prompt`, `--sort`, `--reverse` and `--tool` flags as
`menu`, and shares one usage history with it: `--sort=frequent` ranks by
the same choices either command recorded.

Entries are never decrypted until one is chosen — the picker lists names
only. After the choice, binpass waits 150&nbsp;ms for the picker's window
to close and focus to return, then types.

`--field=otp` and `otp menu` float entries that have produced a code
before to the top of the list, so a store full of plain passwords stops
burying the 2FA ones. The ranking is learned from use, never from
decrypting the store up front, so the very first run starts unranked and
the cache fills as codes are generated. It self-heals: an entry that no
longer holds an `otpauth://` URI is dropped from the ranking on the first
failed pick, rather than sticking until the file is deleted by hand. The
float survives `--reverse` on purpose — a flag meant to flip a name sort
must not bury the 2FA entries again.

`binpass otp --watch` feeds the same ranking: watching proves the entry
produces codes just as surely as emitting one does.

## 5. The security model, stated plainly

**The secret travels on standard input, never as an argument.** On a
multi-user machine, ps(1) shows every process's command line to every
user, and a secret passed as an argument would sit there for the process's
lifetime. Every backend is invoked with a fixed argument table that ends
in a stdin marker:

```
wtype -                                     # text on stdin
xdotool type --clearmodifiers --file -      # text on stdin
ydotool type --file -                       # text on stdin
```

There is no code path that puts the secret in argv — not as a fallback,
not under a flag.

What typing does **not** protect against is the receiving end. Typing
sends the secret through the input stack to whatever has focus; if you
type into the wrong window, that window receives it, exactly as if you
had typed it yourself. The `--delay` flag and the menu's settle pause
exist to make focus predictable, not to guarantee it. A locked screen
refuses the keystrokes, which is the correct outcome.

The clipboard is never involved, so nothing is left there to restore,
clear or steal — but also nothing warns you that the tool typed into a
window you did not mean. Check your focus before the delay runs out.

## 6. What the Nix package ships

The Nix package wraps the binary with `wtype` and `xdotool` on its `PATH`,
so a stock install can type on either session. The session variables gate
which one runs, so neither ever executes in the wrong session — the
wrapper only makes them *findable*.

`ydotool` is deliberately not wrapped. It needs `ydotoold` running and
membership of an input group (uinput permissions), and those are
system-level decisions no wrapper can make on your behalf: silently
shipping a daemon that can inject keystrokes as your user, and a group
membership that grants exactly that, is not a dependency a password
manager should install for you. If you want `ydotool`, install and enable
it yourself — then `--tool=ydotool` works like any other override.

## 7. When typing is the wrong tool

* **Password managers in browsers** — the extension is already in the
  right field; typing races its own autofill.
* **Terminals with bracketed paste or slow rendering** — keystrokes can
  arrive reordered or dropped; a paste is one atomic event.
* **Anything that can take a paste** — `binpass show --clip` restores the
  clipboard's previous contents afterwards; typing has no such undo, and
  no way to know it landed correctly.

macOS and Windows have no wrapped tool in this list; on macOS the
clipboard path is `pbcopy`, and typing needs a tool you supply yourself.
