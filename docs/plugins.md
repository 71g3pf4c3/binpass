# Writing binpass plugins

A plugin is an executable named `binpass-<name>` on your `PATH`. That is the
whole mechanism. If you have written a `kubectl` or a `git` plugin, you
already know how this works.

```sh
cat > ~/.local/bin/binpass-hello <<'EOF'
#!/usr/bin/env bash
echo "hello, $*"
EOF
chmod +x ~/.local/bin/binpass-hello

binpass hello world      # hello, world
```

No manifest, no registration, no restart. Drop the file in, run the command.

> Implements [ARCHITECTURE.md](../ARCHITECTURE.md) §4. Code lives in
> `pkg/plugin/`, the command in `internal/cli/plugin.go`.

---

## Contents

1. [Why not bash functions](#1-why-not-bash-functions)
2. [Naming](#2-naming)
3. [What your plugin receives](#3-what-your-plugin-receives)
4. [Talking back to binpass](#4-talking-back-to-binpass)
5. [Managed plugins and capabilities](#5-managed-plugins-and-capabilities)
6. [A worked example](#6-a-worked-example)
7. [Debugging](#7-debugging)
8. [Security, stated plainly](#8-security-stated-plainly)
9. [What is not built yet](#9-what-is-not-built-yet)

---

## 1. Why not bash functions

pass extends itself by sourcing shell functions, which gives an extension the
run of pass's internals and turns every internal detail into a public
interface that can never be changed. binpass gives you a stable command line
instead, and your plugin can be written in anything that can be executed.

---

## 2. Naming

| File | Command |
|---|---|
| `binpass-hello` | `binpass hello` |
| `binpass-cloud_sync` | `binpass cloud-sync` |
| `binpass-cloud-sync` | `binpass cloud sync` |

Underscores in a file name become dashes in the command. Dashes separate
subcommands. This is the `kubectl` convention, and it exists because
otherwise there is no way to tell "one command with a dash in its name" from
"a subcommand of another plugin".

The longest match wins. With both `binpass-cloud` and `binpass-cloud-sync`
installed, `binpass cloud sync now` runs the latter and passes it `now`.

**Built-in commands always win.** A file named `binpass-show` will never run,
because replacing the commands that handle secrets is not something a file
appearing on `PATH` should be able to do. `binpass plugin list` reports such a
plugin rather than leaving you to wonder.

### Where binpass looks

In order:

1. `$XDG_DATA_HOME/binpass/plugins/<name>/` — managed plugins, installed
   deliberately, and the only ones that can carry a manifest.
2. `$PASSWORD_STORE_DIR/.binpass/plugins/<name>/` — plugins that travel with
   the store when it syncs. Convenient, and a trust decision: anything that
   can write to your store can add one.
3. Anywhere on `PATH`.

Earlier sources win when a name repeats.

---

## 3. What your plugin receives

Arguments are passed through untouched, flags included. binpass resolves the
plugin before it parses anything, so `--dry-run` reaches you rather than being
rejected as an unknown binpass flag.

These variables are set:

| Variable | Meaning |
|---|---|
| `BINPASS_BIN` | Absolute path back to binpass. Use this, never `PATH`. |
| `BINPASS_STORE` | The password store directory. |
| `BINPASS_VERSION` | The version that launched you. |
| `BINPASS_API` | Contract version, currently `1`. |
| `BINPASS_PLUGIN_DIR` | Your own directory, for data files. |
| `BINPASS_PLUGIN` | Your name, set for managed plugins. |
| `BINPASS_PLUGIN_CAPABILITIES` | Your grant as JSON, set for managed plugins. |
| `PASSWORD_STORE_DIR` | Same as `BINPASS_STORE`, for pass-era scripts. |

Your exit status becomes binpass's exit status, so a wrapper script can tell
whether you succeeded.

`BINPASS_PLUGIN`, `BINPASS_PLUGIN_CAPABILITIES`, `PASSWORD_STORE_DIR`, and
`BINPASS_STORE` are stripped from the environment binpass inherited and set
from values it controls. A plugin cannot be handed a forged grant, and cannot
be pointed at a different store, by whatever invoked binpass.

---

## 4. Talking back to binpass

Call `$BINPASS_BIN` and ask for machine-readable output. Never parse the
human-readable kind: it is formatted for people and will change.

```bash
#!/usr/bin/env bash
set -euo pipefail
: "${BINPASS_BIN:?run me through binpass}" "${BINPASS_STORE:?}"

# Refuse an API you were not written for, rather than misbehaving.
[ "${BINPASS_API:-0}" = 1 ] || { echo "need BINPASS_API=1" >&2; exit 1; }

"$BINPASS_BIN" ls --format=json | jq -r '.[]' | while read -r entry; do
    user=$("$BINPASS_BIN" show --field=username "$entry" 2>/dev/null) || continue
    printf '%s\t%s\n' "$entry" "$user"
done
```

`--format=json` and `--format=plain` are the stable surface. Anything that
would break a plugin comes with a new `BINPASS_API`.

Always go through `$BINPASS_BIN` rather than reading `$BINPASS_STORE`
directly. Reading files yourself means reimplementing decryption, missing the
tomb entirely, and — if your plugin is managed — silently escaping the
capability checks the user approved.

---

## 5. Managed plugins and capabilities

A plugin on `PATH` runs with your full authority. A plugin installed into
`$XDG_DATA_HOME/binpass/plugins/<name>/` can carry a manifest declaring what
it needs, and binpass then holds it to that declaration.

### The manifest

`$XDG_DATA_HOME/binpass/plugins/inventory/plugin.yaml`:

```yaml
name: inventory
version: 0.1.0
description: Lists which accounts have a username set.
api: 1
level: 1
exec: binpass-inventory      # optional; defaults to binpass-<name>
capabilities:
  read_paths:
    - "github.com/*"
    - "work/**"
  # decrypt is absent, so this plugin can never see a password.
```

Put the executable beside it in the same directory.

### What can be requested

| Field | Grants |
|---|---|
| `read_paths` | Listing and reading the named entries. |
| `write_paths` | Creating and modifying the named entries. |
| `decrypt` | Access to plaintext. Separate from reading. |
| `network` | Host allowlist. Absent means no network. |
| `exec` | External binaries the plugin may invoke. |

**Everything denies by default.** An absent list is an empty list, never a
wildcard — otherwise a manifest that requests nothing would receive
everything, and consent would not mean what it says.

Reading and decrypting are deliberately separate. A plugin that audits which
accounts lack a username needs to enumerate the store; it never needs to see
a single password.

### What enforcement actually does

Capabilities are enforced when the plugin calls back into binpass. Listing is
filtered:

```
$ binpass inventory
caps={"read_paths":["github.com/*"]}
--- ls ---
[
  "github.com/alice"
]
```

The store also contains `bank/savings`; the plugin is not told it exists.

Denied operations fail with a reason naming the missing grant:

```
$ "$BINPASS_BIN" show bank/savings
plugin: denied by capabilities: plugin "inventory" did not request decrypt,
so it cannot read secrets
```

Read [§8](#8-security-stated-plainly) for what this does and does not buy
you. In short: it constrains what a plugin obtains *through binpass*. It is
not a sandbox.

---

## 6. A worked example

A plugin that reports which entries have no `username` field, without ever
being able to read a password.

```sh
mkdir -p ~/.local/share/binpass/plugins/audit-usernames
cd ~/.local/share/binpass/plugins/audit-usernames
```

`plugin.yaml`:

```yaml
name: audit-usernames
version: 1.0.0
description: Reports entries with no username field.
api: 1
level: 1
capabilities:
  read_paths:
    - "**"
  decrypt: true
```

`binpass-audit-usernames`:

```bash
#!/usr/bin/env bash
set -euo pipefail
: "${BINPASS_BIN:?run me through binpass}"
[ "${BINPASS_API:-0}" = 1 ] || { echo "need BINPASS_API=1" >&2; exit 1; }

missing=0
while read -r entry; do
    if ! "$BINPASS_BIN" show --field=username "$entry" >/dev/null 2>&1; then
        printf 'no username: %s\n' "$entry"
        missing=$((missing + 1))
    fi
done < <("$BINPASS_BIN" ls --format=json | jq -r '.[]')

printf '\n%d entr%s without a username\n' "$missing" \
    "$([ "$missing" = 1 ] && echo y || echo ies)"
```

```sh
chmod +x binpass-audit-usernames
binpass plugin list
# COMMAND                  PATH                    STATUS
# binpass audit-usernames  /home/you/.local/...    ok

binpass audit-usernames
```

This one needs `decrypt: true` because it inspects fields. Drop that line and
every `show` is refused:

```
plugin: denied by capabilities: plugin "audit-usernames" did not request
decrypt, so it cannot read secrets
```

Which is exactly what you want when reviewing someone else's plugin and you
are not yet convinced it deserves your passwords.

Note what the script above does with that refusal: `show ... >/dev/null 2>&1`
swallows it, so a denied entry looks identical to one that genuinely has no
username, and the plugin reports nonsense with a straight face. Distinguish
the two — a plugin that cannot tell "forbidden" from "absent" will mislead
whoever runs it:

```bash
if out=$("$BINPASS_BIN" show --field=username "$entry" 2>&1); then
    : # has one
elif [[ "$out" == *"denied by capabilities"* ]]; then
    echo "refused: $entry (grant decrypt to audit this)" >&2
else
    printf 'no username: %s\n' "$entry"
fi
```

---

## 7. Debugging

```sh
binpass plugin list
```

It lists every `binpass-*` file it can see, including the ones that will not
run and why:

```
COMMAND             PATH                          STATUS
binpass hello       /home/you/.local/bin/...      ok
binpass notexec     /home/you/.local/bin/...      not executable
binpass dup         /usr/local/bin/binpass-dup    shadowed by /home/you/...
binpass show        /home/you/.local/bin/...      shadowed by the builtin command show
```

Three quarters of plugin problems are one of: the executable bit is not set,
another copy sits earlier on `PATH`, or the name collides with a built-in.

Two more worth knowing:

* **`binpass: unknown command`** — the file is not on `PATH` at all, or is
  named `binpass_foo` rather than `binpass-foo`.
* **Your plugin runs but sees an empty store** — you are almost certainly
  managed and scoped. Check `BINPASS_PLUGIN_CAPABILITIES`; a `read_paths`
  that matches nothing looks exactly like an empty store.

To see what your plugin receives:

```sh
cat > ~/.local/bin/binpass-env <<'EOF'
#!/usr/bin/env bash
env | grep -E '^(BINPASS|PASSWORD_STORE)' | sort
echo "args: $*"
EOF
chmod +x ~/.local/bin/binpass-env
binpass env --some-flag
```

---

## 8. Security, stated plainly

A plugin is an ordinary program running as you. It can read your store
directly, ignore binpass entirely, and do anything you could do. Installing
one is exactly as dangerous as running any other program someone sent you.

binpass does not sandbox plugins and does not pretend to. What it does:

* Built-in commands cannot be shadowed, so the commands that touch secrets
  stay binpass's own.
* Plugins run in their own process group, so a plugin cannot signal binpass
  or its siblings, and a runaway plugin's whole tree can be cleaned up.
* `BINPASS_PLUGIN_CAPABILITIES` and `PASSWORD_STORE_DIR` are stripped from the
  inherited environment and set from values binpass controls, so a plugin
  cannot be handed a forged grant or be pointed at another store by whatever
  invoked binpass.
* Capabilities are enforced on every call a managed plugin makes back into
  binpass.

What that last point is worth, precisely: a plugin declaring `read_paths:
["github.com/*"]` cannot use binpass to read `bank/savings`. It can still open
`~/.password-store/bank/savings.age` with its own two hands. If it has your
identity file, it can decrypt it. The capability model is a guard rail
against a careless plugin and an audit trail of what each one asked for. It
is not a boundary against a hostile one.

Read a plugin before you install it. That is the actual security boundary,
and no amount of engineering on our side replaces it.

---

## 9. What is not built yet

Being straight about the gap between the architecture and the code:

| Feature | Status |
|---|---|
| Level 1 (executables) | **Working.** Everything above. |
| Capability enforcement | **Working** for managed plugins. |
| Level 2 (declarative YAML recipes) | Manifests parse `level: 2`, but no recipe interpreter exists. |
| Level 3 (WASM under wazero) | Not built. This is where isolation would be real: a guest with no file or network access. |
| `binpass plugin install` / `remove` | Not built. Install by creating the directory yourself, as in [§6](#6-a-worked-example). |
| Approval prompt and `plugins.lock` | The lock format and the "has this changed since you approved it" check are implemented and tested in `pkg/plugin`, but nothing calls them yet. A manifest is currently trusted on sight. |

That last row matters if you are relying on capabilities: today the manifest
in the directory is what gets enforced, and editing it to ask for more will
not prompt anyone. Until the approval flow is wired up, treat a managed
plugin's manifest as documentation of intent rather than as consent you gave.
