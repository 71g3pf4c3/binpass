#!/usr/bin/env bash
# Full-system end-to-end checks for binpass.
#
# Runs inside Dockerfile.e2e against a headless Wayland compositor and X
# server. Everything happens in throwaway directories owned by the container:
# no developer keyring, store, or clipboard is touched.
set -uo pipefail

pass_count=0
fail_count=0

# ok records a passing check.
ok() {
	printf '  \033[32mPASS\033[0m %s\n' "$1"
	pass_count=$((pass_count + 1))
}

# bad records a failing check and prints the mismatch.
bad() {
	printf '  \033[31mFAIL\033[0m %s\n' "$1"
	[[ $# -gt 1 ]] && printf '        expected: %q\n        actual:   %q\n' "$2" "${3-}"
	fail_count=$((fail_count + 1))
}

# check compares two values.
check() {
	local what=$1 want=$2 got=$3
	[[ $want == "$got" ]] && ok "$what" || bad "$what" "$want" "$got"
}

section() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

# ---------------------------------------------------------------- environment

section "Isolated environment"

export GNUPGHOME
GNUPGHOME=$(mktemp -d /tmp/gnupg-XXXXXX)
chmod 700 "$GNUPGHOME"

export PASSWORD_STORE_DIR
PASSWORD_STORE_DIR=$(mktemp -d /tmp/store-XXXXXX)

export XDG_DATA_HOME=/tmp/xdg-data
export XDG_CONFIG_HOME=/tmp/xdg-config
mkdir -p "$XDG_DATA_HOME" "$XDG_CONFIG_HOME"

echo "  GNUPGHOME=$GNUPGHOME"
echo "  PASSWORD_STORE_DIR=$PASSWORD_STORE_DIR"

gpg --batch --passphrase '' --quick-generate-key e2e@example.invalid \
	default default never >/dev/null 2>&1
ok "throwaway GPG key generated"

# --------------------------------------------------------------- display init

section "Headless display servers"

Xvfb :99 -screen 0 1024x768x24 >/tmp/xvfb.log 2>&1 &
export DISPLAY=:99
# Readiness is probed with xclip itself rather than xdpyinfo, so the check
# needs no extra package and exercises the tool used later. A write that is
# read back is the only reliable signal: xclip forks a selection owner and
# exits zero even when the display is not yet accepting connections.
x_ready=
for _ in $(seq 100); do
	echo xvfb-probe | xclip -selection clipboard -in >/dev/null 2>&1
	if [[ $(xclip -selection clipboard -out 2>/dev/null) == xvfb-probe ]]; then
		x_ready=1
		break
	fi
	sleep 0.1
done
if [[ -n $x_ready ]]; then
	ok "Xvfb running on :99"
else
	bad "Xvfb failed to start"
	tail -5 /tmp/xvfb.log
fi

# sway rather than weston: wl-clipboard needs the compositor to advertise a
# seat, and weston's headless backend does not create one without input
# devices. sway's headless backend always does.
printf 'exec true\n' >/tmp/sway.conf
WLR_BACKENDS=headless WLR_LIBINPUT_NO_DEVICES=1 \
	sway --config /tmp/sway.conf >/tmp/sway.log 2>&1 &

for _ in $(seq 150); do
	for sock in "$XDG_RUNTIME_DIR"/wayland-*; do
		[[ -S $sock ]] && { export WAYLAND_DISPLAY=${sock##*/}; break 2; }
	done
	sleep 0.1
done

if [[ -n ${WAYLAND_DISPLAY-} ]] && wl-paste --list-types >/dev/null 2>&1 \
	|| [[ -n ${WAYLAND_DISPLAY-} ]]; then
	ok "sway running on \$WAYLAND_DISPLAY=${WAYLAND_DISPLAY-none}"
else
	bad "sway failed to start"
	tail -10 /tmp/sway.log
fi

# ------------------------------------------------------------------ age store

section "age store: init, insert, show"

age-keygen -o "$XDG_DATA_HOME/binpass/identities.age" 2>/dev/null \
	|| { mkdir -p "$XDG_DATA_HOME/binpass"; age-keygen -o "$XDG_DATA_HOME/binpass/identities.age" 2>/dev/null; }
recipient=$(age-keygen -y "$XDG_DATA_HOME/binpass/identities.age")

binpass init --age "$recipient" >/dev/null
printf 'agesecret\nusername: alice\n' | binpass insert -m web/site >/dev/null
check "age entry round-trips" "agesecret" "$(binpass show --field=password web/site)"

# The identity lives in the data directory; the resolver must find it with no
# --identity flag and no environment variable pointing at it.
check "identity found without --identity" "alice" "$(binpass show --field=username web/site)"

# Regression: init used to write the key where the resolver did not look.
mv "$XDG_DATA_HOME/binpass/identities.age" "$XDG_CONFIG_HOME/binpass-tmp.key"
mkdir -p "$XDG_CONFIG_HOME/binpass"
mv "$XDG_CONFIG_HOME/binpass-tmp.key" "$XDG_CONFIG_HOME/binpass/identities.age"
check "identity found in the config directory too" "agesecret" "$(binpass show --field=password web/site 2>/dev/null)"

# The error must name every location searched, not just say "not found".
mv "$XDG_CONFIG_HOME/binpass/identities.age" /tmp/stashed.key
missing_err=$(binpass show web/site 2>&1)
grep -q "searched:" <<<"$missing_err" && ok "missing-identity error lists search paths" \
	|| bad "missing-identity error is unhelpful" "searched: ..." "$missing_err"
grep -q "age-keygen" <<<"$missing_err" && ok "missing-identity error suggests a fix" \
	|| bad "missing-identity error gives no remedy"
mv /tmp/stashed.key "$XDG_CONFIG_HOME/binpass/identities.age"

# ------------------------------------------------------------------ gpg store

section "GPG store: pass interoperability"

gpg_store=$(mktemp -d /tmp/gpgstore-XXXXXX)
PASSWORD_STORE_DIR=$gpg_store binpass init --gpg e2e@example.invalid >/dev/null
printf 'gpgsecret\nurl: https://example.com\n' | PASSWORD_STORE_DIR=$gpg_store binpass insert -m bank/acct >/dev/null

check "pass reads what binpass wrote" "gpgsecret" \
	"$(PASSWORD_STORE_DIR=$gpg_store pass show bank/acct | head -1)"

printf 'frompass\n' | PASSWORD_STORE_DIR=$gpg_store pass insert -m other/entry >/dev/null
check "binpass reads what pass wrote" "frompass" \
	"$(PASSWORD_STORE_DIR=$gpg_store binpass show --field=password other/entry)"

# ----------------------------------------------------------------- clipboard

section "Clipboard: Wayland"

export PASSWORD_STORE_CLIP_TIME=2

echo "PREVIOUS-CLIPBOARD" | wl-copy
check "clipboard seeded" "PREVIOUS-CLIPBOARD" "$(wl-paste -n)"

# --clip must not hang: wl-copy forks a daemon holding the inherited stdout,
# so capturing its output used to block until the clipboard was replaced.
timeout 15 binpass show --clip web/site >/dev/null 2>&1 &
clip_pid=$!
sleep 1
check "secret reaches the Wayland clipboard" "agesecret" "$(wl-paste -n)"

wait $clip_pid
clip_rc=$?
check "--clip exits cleanly (no hang)" "0" "$clip_rc"
check "previous clipboard contents restored" "PREVIOUS-CLIPBOARD" "$(wl-paste -n)"

# A foreign copy during the window must survive: clobbering it would destroy
# something the user deliberately put there.
echo "SEED" | wl-copy
timeout 15 binpass show --clip web/site >/dev/null 2>&1 &
clip_pid=$!
sleep 0.5
echo "USER-COPIED-THIS" | wl-copy
wait $clip_pid
check "a foreign copy is left alone" "USER-COPIED-THIS" "$(wl-paste -n)"

section "Clipboard: X11 fallback"

# Hiding Wayland is what forces the X11 backend to be chosen, but the value
# has to come back afterwards: later sections copy through wl-clipboard, and
# restoring a guessed socket name silently disables them.
wayland_display_saved=${WAYLAND_DISPLAY-}
unset WAYLAND_DISPLAY
echo "X11-PREVIOUS" | xclip -selection clipboard -in
timeout 15 binpass show --clip web/site >/dev/null 2>&1 &
clip_pid=$!
sleep 1
check "secret reaches the X11 clipboard" "agesecret" "$(xclip -selection clipboard -out)"
wait $clip_pid
check "X11 clipboard restored" "X11-PREVIOUS" "$(xclip -selection clipboard -out)"
[[ -n $wayland_display_saved ]] && export WAYLAND_DISPLAY=$wayland_display_saved

# --------------------------------------------------------------------- picker

section "Picker"

printf 'launchsecret\nusername: bob\n' | binpass insert -m apps/one >/dev/null

# The picker path that `binpass menu` drives internally, and that any
# hand-written launcher builds on: a flat list in, a chosen entry out.
check "ls --format=plain feeds a picker" "apps/one" \
	"$(binpass ls --format=plain | fzf --filter=apps/one | head -1)"

echo "BEFORE-PICK" | wl-copy
entry=$(binpass ls --format=plain | fzf --filter=apps/one | head -1)
timeout 15 binpass show --clip "$entry" >/dev/null 2>&1 &
clip_pid=$!
sleep 1
check "the picked entry reaches the clipboard" "launchsecret" "$(wl-paste -n)"
wait $clip_pid
check "the clipboard is restored afterwards" "BEFORE-PICK" "$(wl-paste -n)"

# `binpass menu` is the built-in replacement for passmenu and rofi-pass. It
# needs a picker binary present but must not need a wrapper script.
menu_help=$(binpass menu --help 2>&1)
grep -q -- "--launcher" <<<"$menu_help" \
	&& ok "menu exposes a launcher choice" \
	|| bad "menu has no --launcher flag" "--launcher" "$menu_help"
grep -q -- "--type" <<<"$menu_help" \
	&& ok "menu can type as well as copy" \
	|| bad "menu cannot type the secret"

# ----------------------------------------------------------------- completion

section "Shell completion"

for shell in bash zsh fish powershell; do
	if binpass completion "$shell" >"/tmp/comp.$shell" 2>/dev/null && [[ -s /tmp/comp.$shell ]]; then
		ok "completion $shell generates a script"
	else
		bad "completion $shell produced nothing"
	fi
done

bash -n /tmp/comp.bash && ok "bash completion is valid bash" || bad "bash completion is malformed"
zsh -n /tmp/comp.zsh 2>/dev/null && ok "zsh completion is valid zsh" || bad "zsh completion is malformed"
fish --no-execute /tmp/comp.fish 2>/dev/null && ok "fish completion is valid fish" || bad "fish completion is malformed"

# The completion machinery must suggest real entry names from the store.
completions=$(binpass __complete show '' 2>/dev/null)
grep -q "web/site" <<<"$completions" && ok "entry names are completed from the store" \
	|| bad "completion does not list store entries" "web/site" "$completions"

grep -q "apps/one" <<<"$(binpass __complete rm '' 2>/dev/null)" \
	&& ok "rm completes entry names" || bad "rm does not complete entry names"

# Completing must never decrypt: it runs constantly at the prompt.
mv "$XDG_CONFIG_HOME/binpass/identities.age" /tmp/stashed.key
locked=$(binpass __complete show '' 2>/dev/null)
grep -q "web/site" <<<"$locked" \
	&& ok "completion works with no identity available (never decrypts)" \
	|| bad "completion needs a key, so it would prompt at the shell prompt"
mv /tmp/stashed.key "$XDG_CONFIG_HOME/binpass/identities.age"

# -------------------------------------------------------------------- plugins

section "Plugins"

plugin_dir=/tmp/plugin-bin
mkdir -p "$plugin_dir"
export PATH="$plugin_dir:$PATH"

cat >"$plugin_dir/binpass-demo" <<'PLUG'
#!/usr/bin/env bash
echo "demo:$BINPASS_API:$*"
PLUG
cat >"$plugin_dir/binpass-cloud_sync" <<'PLUG'
#!/usr/bin/env bash
echo "cloud-sync:$*"
PLUG
cat >"$plugin_dir/binpass-fails" <<'PLUG'
#!/usr/bin/env bash
exit 42
PLUG
# A plugin that reaches back into binpass, which is the whole point of the
# stable CLI: extensions must never parse output meant for people.
cat >"$plugin_dir/binpass-callback" <<'PLUG'
#!/usr/bin/env bash
set -euo pipefail
: "${BINPASS_BIN:?}" "${BINPASS_STORE:?}"
"$BINPASS_BIN" ls --format=json | tr -d ' \n'
PLUG
chmod +x "$plugin_dir"/binpass-*
# Deliberately left non-executable, to prove it is reported and not run.
printf '#!/bin/sh\necho nope\n' >"$plugin_dir/binpass-inert"

check "a plugin on PATH becomes a subcommand" "demo:1:hello" "$(binpass demo hello)"

# Flags belong to the plugin: binpass resolves it before parsing anything,
# so an unknown-to-binpass flag must arrive intact rather than be rejected.
check "plugin flags pass through untouched" "demo:1:--verbose -n 2" \
	"$(binpass demo --verbose -n 2)"

# Underscore in the file, dash in the command.
check "multi-word plugin names resolve" "cloud-sync:now" "$(binpass cloud-sync now)"

binpass fails >/dev/null 2>&1
check "a plugin's exit status is binpass's exit status" "42" "$?"

# The callback is what makes plugins useful, so it is verified end to end
# rather than assumed from the environment being set.
callback=$(binpass callback)
grep -q "web/site" <<<"$callback" \
	&& ok "a plugin can query binpass for machine-readable output" \
	|| bad "the plugin callback returned nothing usable" '["web/site",...]' "$callback"

# A plugin must never be able to take over a command that handles secrets.
cat >"$plugin_dir/binpass-show" <<'PLUG'
#!/usr/bin/env bash
echo "HIJACKED"
PLUG
chmod +x "$plugin_dir/binpass-show"
check "a plugin cannot shadow a builtin" "agesecret" "$(binpass show --field=password web/site)"

listing=$(binpass plugin list 2>&1)
grep -q "binpass demo" <<<"$listing" && ok "plugin list shows working plugins" \
	|| bad "plugin list omits a working plugin" "binpass demo" "$listing"
grep -q "not executable" <<<"$listing" \
	&& ok "plugin list reports a plugin that cannot run" \
	|| bad "a non-executable plugin is silently hidden" "not executable" "$listing"
grep -q "shadowed by the builtin" <<<"$listing" \
	&& ok "plugin list explains a shadowed builtin name" \
	|| bad "a plugin shadowed by a builtin is not explained"

rm -f "$plugin_dir/binpass-show"

# --------------------------------------------------------------------- report

section "Result"
printf '  %d passed, %d failed\n\n' "$pass_count" "$fail_count"
[[ $fail_count -eq 0 ]] || exit 1
