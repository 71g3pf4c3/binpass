#!/usr/bin/env bash
# Desktop integration checks for binpass: clipboard and typing on real X11.
#
# Runs inside Dockerfile.desktop against an Xvfb display with the real
# xclip, xsel, xdotool, xterm and dmenu — the binaries a Linux desktop
# actually has. The unit-suite stubs prove the secrets travel over stdin;
# only the real tools prove the X server accepts the arguments, the
# selections round-trip and the keystrokes land in a focused window.
#
# Everything happens in throwaway directories owned by the container: no
# developer keyring, store, or clipboard is touched. The Wayland backends
# (wl-copy, wtype) need a compositor and are exercised by Dockerfile.e2e.
set -uo pipefail

pass_count=0
fail_count=0

ok() {
	printf '  \033[32mPASS\033[0m %s\n' "$1"
	pass_count=$((pass_count + 1))
}

bad() {
	printf '  \033[31mFAIL\033[0m %s\n' "$1"
	[[ $# -gt 1 ]] && printf '        expected: %q\n        actual:   %q\n' "$2" "${3-}"
	fail_count=$((fail_count + 1))
}

check() {
	local what=$1 want=$2 got=$3
	[[ $want == "$got" ]] && ok "$what" || bad "$what" "$want" "$got"
}

section() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

# ---------------------------------------------------------------- environment

section "Isolated environment"

export HOME=/tmp/desktop-home
export XDG_CONFIG_HOME="$HOME/.config"
export XDG_DATA_HOME="$HOME/.local/share"
export PASSWORD_STORE_DIR="$HOME/store"
export BINPASS_CONFIG="$HOME/nonexistent.yaml"
mkdir -p "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" "$PASSWORD_STORE_DIR"

go build -o /usr/local/bin/binpass ./cmd/binpass

age-keygen -o "$XDG_DATA_HOME/binpass/identities.age" 2>/dev/null \
	|| { mkdir -p "$XDG_DATA_HOME/binpass"; age-keygen -o "$XDG_DATA_HOME/binpass/identities.age" 2>/dev/null; }
recipient=$(age-keygen -y "$XDG_DATA_HOME/binpass/identities.age")

binpass init --age "$recipient" >/dev/null
printf 'typed-secret 42\nusername: alice\n' | binpass insert -m web/site >/dev/null
printf 'launchsecret\n' | binpass insert -m apps/one >/dev/null
ok "throwaway age store initialised"

# --------------------------------------------------------------- display init

section "Headless X server"

Xvfb :99 -screen 0 1024x768x24 >/tmp/xvfb.log 2>&1 &
export DISPLAY=:99
# Readiness is probed with xclip itself, the same way e2e-session.sh does
# it: a write that is read back is the only reliable signal, and the probe
# exercises the tool the later checks depend on.
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
	exit 1
fi

# ------------------------------------------------------------------ clipboard

section "Clipboard: xclip"

export PASSWORD_STORE_CLIP_TIME=2

echo "X11-PREVIOUS" | xclip -selection clipboard -in
timeout 15 binpass show --clip web/site >/dev/null 2>&1 &
clip_pid=$!
sleep 1
check "secret reaches the X11 clipboard" "typed-secret 42" "$(xclip -selection clipboard -out)"
wait $clip_pid
check "--clip exits cleanly (no hang)" "0" "$?"
check "X11 clipboard restored" "X11-PREVIOUS" "$(xclip -selection clipboard -out)"

# A foreign copy during the window must survive: clobbering it would
# destroy something the user deliberately put there.
echo "SEED" | xclip -selection clipboard -in
timeout 15 binpass show --clip web/site >/dev/null 2>&1 &
clip_pid=$!
sleep 0.5
echo "USER-COPIED-THIS" | xclip -selection clipboard -in
wait $clip_pid
check "a foreign copy is left alone" "USER-COPIED-THIS" "$(xclip -selection clipboard -out)"

section "Clipboard: xsel"

# xclip is preferred when both are installed, so the xsel backend is reached
# the same way a machine with only xsel presents it: a PATH where xclip is
# absent. binpass is invoked by absolute path, so it survives the diet — and
# timeout must be too, because the shell resolves it against the very PATH
# being narrowed.
xsel_only=/tmp/xsel-only
mkdir -p "$xsel_only"
ln -sf "$(command -v xsel)" "$xsel_only/xsel"

echo "XSEL-PREVIOUS" | xsel --clipboard --input
PATH="$xsel_only" /usr/bin/timeout 15 /usr/local/bin/binpass show --clip web/site >/dev/null 2>&1 &
clip_pid=$!
sleep 1
check "secret reaches the clipboard through xsel" "typed-secret 42" "$(xsel --clipboard --output)"
wait $clip_pid
check "xsel --clip exits cleanly (no hang)" "0" "$?"
check "xsel clipboard restored" "XSEL-PREVIOUS" "$(xsel --clipboard --output)"

# --------------------------------------------------------------------- typing

section "Typing: xdotool into a real X client"

# typed_check starts a fresh xterm receiver, focuses it, runs the given
# binpass invocation, and checks that the secret landed in the file.
#
# xterm with a raw, echo-less tty is the receiver: whatever is typed into
# its window lands in the file, byte for byte, with no line discipline in
# between. Each check gets its own xterm: reusing one means deleting the
# file under cat's open descriptor, and the second secret would be written
# to an unlinked inode no assertion can ever read. No window manager is
# running, so focus is assigned explicitly — xdotool's windowfocus is a
# plain XSetInputFocus and needs no EWMH.
typed_check() {
	local what=$1 typed=$2
	shift 2
	rm -f "$typed"
	xterm -e sh -c "stty raw -echo; cat > '$typed'" >/tmp/xterm.log 2>&1 &
	local xterm_pid=$!

	local wid=
	for _ in $(seq 100); do
		wid=$(xdotool search --class xterm 2>/dev/null | tail -1)
		[[ -n $wid ]] && break
		sleep 0.1
	done
	if [[ -z $wid ]]; then
		bad "$what (the receiver window never appeared)"
		kill "$xterm_pid" 2>/dev/null || true
		return
	fi
	xdotool windowfocus --sync "$wid"

	if "$@"; then
		ok "$what (binpass type exits cleanly)"
	else
		bad "$what (binpass type failed)"
	fi

	local got=
	for _ in $(seq 100); do
		if [[ -s $typed ]]; then got=$(cat "$typed"); break; fi
		sleep 0.1
	done
	check "$what" "typed-secret 42" "$got"

	kill "$xterm_pid" 2>/dev/null || true
	# Wait for the window to disappear, so the next receiver search cannot
	# grab a dying window's id.
	for _ in $(seq 100); do
		xdotool search --class xterm >/dev/null 2>&1 || break
		sleep 0.1
	done
}

typed_check "the keystrokes reach the X client" /tmp/typed.txt \
	binpass type web/site

# --tool forces the backend by name; the forced path must drive the real
# xdotool exactly like the detected one.
typed_check "--tool xdotool reaches the X client too" /tmp/typed-tool.txt \
	binpass type --tool xdotool web/site

# --------------------------------------------------------------------- picker

section "Picker: dmenu"

# dmenu is the picker a bare X session has. It grabs the keyboard, so the
# synthetic events go to it regardless of focus; typing filters the store
# to one entry and Return commits the choice.
rm -f /tmp/menu.out
timeout 60 binpass menu --launcher dmenu --print >/tmp/menu.out 2>/tmp/menu.err &
menu_pid=$!

dmenu_win=
for _ in $(seq 100); do
	dmenu_win=$(xdotool search --class dmenu 2>/dev/null | tail -1)
	[[ -n $dmenu_win ]] && break
	sleep 0.1
done

if [[ -n $dmenu_win ]]; then
	ok "dmenu drew its window"
	xdotool type -- web/site
	xdotool key Return
	wait $menu_pid
	check "menu exited cleanly" "0" "$?"
	check "the picked entry's secret is printed" "typed-secret 42" "$(cat /tmp/menu.out)"
else
	bad "dmenu never appeared"
	kill "$menu_pid" 2>/dev/null || true
	cat /tmp/menu.err >&2
fi

# --------------------------------------------------------------------- report

section "Result"
printf '  %d passed, %d failed\n\n' "$pass_count" "$fail_count"
[[ $fail_count -eq 0 ]] || exit 1
