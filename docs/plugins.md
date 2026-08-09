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

## Why not bash functions

pass extends itself by sourcing shell functions, which gives an extension the
run of pass's internals and turns every internal detail into a public
interface that can never be changed. binpass gives you a stable command line
instead, and your plugin can be written in anything that can be executed.

## Naming

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

## What your plugin receives

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
| `PASSWORD_STORE_DIR` | Same as `BINPASS_STORE`, for pass-era scripts. |

Your exit status becomes binpass's exit status, so a wrapper script can tell
whether you succeeded.

## Talking back to binpass

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

## Debugging

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

## Security, stated plainly

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

Read a plugin before you install it. That is the actual security boundary,
and no amount of engineering on our side replaces it.
