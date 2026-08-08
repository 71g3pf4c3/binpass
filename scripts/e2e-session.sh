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
# needs no extra package and tests the tool actually used later.
for _ in $(seq 100); do
	xclip -selection clipboard -o >/dev/null 2>&1 && break
	echo probe | xclip -selection clipboard -in >/dev/null 2>&1 && break
	sleep 0.1
done
if echo probe | xclip -selection clipboard -in >/dev/null 2>&1; then
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

unset WAYLAND_DISPLAY
echo "X11-PREVIOUS" | xclip -selection clipboard -in
timeout 15 binpass show --clip web/site >/dev/null 2>&1 &
clip_pid=$!
sleep 1
check "secret reaches the X11 clipboard" "agesecret" "$(xclip -selection clipboard -out)"
wait $clip_pid
check "X11 clipboard restored" "X11-PREVIOUS" "$(xclip -selection clipboard -out)"
export WAYLAND_DISPLAY=wayland-e2e

# ------------------------------------------------------------------ launchers

section "Launcher scripts"

printf 'launchsecret\nusername: bob\n' | binpass insert -m apps/one >/dev/null

check "ls --format=plain feeds a picker" "apps/one" \
	"$(binpass ls --format=plain | fzf --filter=apps/one | head -1)"

echo "BEFORE-LAUNCHER" | wl-copy
entry=$(binpass ls --format=plain | fzf --filter=apps/one | head -1)
timeout 15 binpass show --clip "$entry" >/dev/null 2>&1 &
clip_pid=$!
sleep 1
check "binpass-fzf path copies the secret" "launchsecret" "$(wl-paste -n)"
wait $clip_pid
check "binpass-fzf path restores the clipboard" "BEFORE-LAUNCHER" "$(wl-paste -n)"

for script in binpass-rofi binpass-fzf binpass-dmenu; do
	bash -n "/usr/local/bin/$script" \
		&& ok "$script is syntactically valid" \
		|| bad "$script has a syntax error"
done

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

# --------------------------------------------------------------------- report

section "Result"
printf '  %d passed, %d failed\n\n' "$pass_count" "$fail_count"
[[ $fail_count -eq 0 ]] || exit 1
