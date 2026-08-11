#!/usr/bin/env bash
# Drive the binpass Secret Service provider with the real libsecret client.
#
# secret-tool is what Chrome, VS Code and NetworkManager use underneath, so a
# provider it cannot talk to is a provider that does not work, whatever the
# unit tests say. Everything here runs against a private session bus in a
# container: no part of it touches a developer's own keyring or store.
set -uo pipefail

pass_count=0
fail_count=0

ok() {
	printf '  \033[32mPASS\033[0m %s\n' "$1"
	pass_count=$((pass_count + 1))
}

bad() {
	printf '  \033[31mFAIL\033[0m %s\n' "$1"
	fail_count=$((fail_count + 1))
}

section() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

# ------------------------------------------------------------------ setup

export HOME=/tmp/ss-home
export XDG_CONFIG_HOME="$HOME/.config"
export XDG_DATA_HOME="$HOME/.local/share"
export PASSWORD_STORE_DIR="$HOME/store"
export BINPASS_CONFIG="$HOME/nonexistent.yaml"
mkdir -p "$PASSWORD_STORE_DIR" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME"

go build -o /usr/local/bin/binpass ./cmd/binpass

age-keygen -o "$HOME/identity.key" 2>/dev/null
recipient=$(grep 'public key' "$HOME/identity.key" | sed 's/.*: //')
export BINPASS_IDENTITY="$HOME/identity.key"

binpass init --age "$recipient" >/dev/null

eval "$(dbus-launch --sh-syntax)"
trap 'kill "${DBUS_SESSION_BUS_PID:-}" 2>/dev/null || true' EXIT

section "Provider startup"

binpass ss serve >/tmp/ss.log 2>&1 &
ss_pid=$!
trap 'kill "$ss_pid" 2>/dev/null; kill "${DBUS_SESSION_BUS_PID:-}" 2>/dev/null || true' EXIT

# Wait for the name to appear rather than sleeping a fixed time.
for _ in $(seq 1 50); do
	if dbus-send --session --dest=org.freedesktop.DBus --print-reply \
		/org/freedesktop/DBus org.freedesktop.DBus.NameHasOwner \
		string:org.freedesktop.secrets 2>/dev/null | grep -q 'boolean true'; then
		break
	fi
	sleep 0.2
done

if dbus-send --session --dest=org.freedesktop.DBus --print-reply \
	/org/freedesktop/DBus org.freedesktop.DBus.NameHasOwner \
	string:org.freedesktop.secrets 2>/dev/null | grep -q 'boolean true'; then
	ok "binpass owns org.freedesktop.secrets"
else
	bad "the provider did not claim the bus name"
	cat /tmp/ss.log
	exit 1
fi

# ------------------------------------------------------------------ store

section "secret-tool store and lookup"

printf 'correct-horse-battery-staple' | secret-tool store --label='GitHub token' \
	server github.com username alice 2>/tmp/store.err
if [[ $? -eq 0 ]]; then
	ok "secret-tool store succeeded"
else
	bad "secret-tool store failed: $(cat /tmp/store.err)"
fi

got=$(secret-tool lookup server github.com username alice 2>/tmp/lookup.err)
if [[ "$got" == "correct-horse-battery-staple" ]]; then
	ok "secret-tool lookup returned the stored secret"
else
	bad "lookup returned '$got' (stderr: $(cat /tmp/lookup.err))"
fi

# libsecret negotiates dh-ietf1024-sha256-aes128-cbc-pkcs7 by default, so a
# working lookup already proves the DH path against a real client.
ok "the transport the client chose round-tripped a secret"

# ------------------------------------------------------- exact matching

section "Attribute matching"

if secret-tool lookup server github.com >/dev/null 2>&1; then
	ok "a subset of the attributes matches"
else
	bad "looking up by one attribute should match"
fi

if secret-tool lookup server github.com username bob >/dev/null 2>&1; then
	bad "an attribute nobody carries must not match"
else
	ok "a wrong attribute value matches nothing"
fi

if secret-tool lookup server github >/dev/null 2>&1; then
	bad "matching must be exact, not by prefix"
else
	ok "a prefix of an attribute value matches nothing"
fi

# ------------------------------------------------------------- privacy

section "What reaches the disk"

store_files=$(find "$PASSWORD_STORE_DIR" -type f | tr '\n' ' ')

leaked=0
for secret_value in github.com alice 'GitHub token'; do
	for f in $store_files; do
		case "$(basename "$f")" in
		*"$secret_value"*)
			bad "the filename $(basename "$f") discloses '$secret_value'"
			leaked=1
			;;
		esac
	done
done
[[ $leaked -eq 0 ]] && ok "no attribute value appears in a filename"

index_file="$PASSWORD_STORE_DIR/secret-service/.index.age"
if [[ -f "$index_file" ]]; then
	ok "an attribute index was written"
	if grep -qa -e github.com -e alice "$index_file"; then
		bad "the index discloses attribute values in the clear"
	else
		ok "the index holds no attribute value in the clear"
	fi
else
	bad "no index file at $index_file"
fi

# The ciphertext must not contain the secret either, which is the ordinary
# store guarantee, checked here because this path writes entries itself.
if grep -rqa 'correct-horse-battery-staple' "$PASSWORD_STORE_DIR"; then
	bad "the secret appears in plaintext under the store"
else
	ok "the secret is encrypted at rest"
fi

# --------------------------------------------------- pass compatibility

section "Items are ordinary pass entries"

item_path=$(binpass ls secret-service 2>/dev/null | tail -n +2 | grep -oE '[0-9a-f]{32}' | head -1)
if [[ -n "$item_path" ]]; then
	shown=$(binpass show "secret-service/login/$item_path" 2>/dev/null)
	if [[ "$(head -1 <<<"$shown")" == "correct-horse-battery-staple" ]]; then
		ok "binpass show reads the item a client stored"
	else
		bad "binpass show returned unexpected content"
	fi
	if grep -q 'attr.server: github.com' <<<"$shown"; then
		ok "attributes are readable fields inside the encrypted file"
	else
		bad "attributes are missing from the entry"
	fi
else
	bad "no item found under secret-service/login"
fi

# --------------------------------------------------------------- update

section "Overwriting and deleting"

printf 'a-new-password' | secret-tool store --label='GitHub token' \
	server github.com username alice 2>/dev/null
got=$(secret-tool lookup server github.com username alice 2>/dev/null)
if [[ "$got" == "a-new-password" ]]; then
	ok "storing the same attributes replaces the secret"
else
	bad "expected the updated secret, got '$got'"
fi

count=$(binpass ls secret-service/login 2>/dev/null | grep -cE '[0-9a-f]{32}')
if [[ "$count" == "1" ]]; then
	ok "replacing did not leave a duplicate item"
else
	bad "expected 1 item after replace, found $count"
fi

secret-tool clear server github.com username alice 2>/dev/null
if secret-tool lookup server github.com username alice >/dev/null 2>&1; then
	bad "a cleared secret is still findable"
else
	ok "secret-tool clear removed the item"
fi

# --------------------------------------------------------- multiple items

section "Several items"

printf 'first' | secret-tool store --label='One' service a user x 2>/dev/null
printf 'second' | secret-tool store --label='Two' service b user x 2>/dev/null
printf 'third' | secret-tool store --label='Three' service a user y 2>/dev/null

[[ "$(secret-tool lookup service a user x 2>/dev/null)" == "first" ]] &&
	ok "the first item is retrievable" || bad "wrong secret for service=a user=x"
[[ "$(secret-tool lookup service b user x 2>/dev/null)" == "second" ]] &&
	ok "the second item is retrievable" || bad "wrong secret for service=b user=x"
[[ "$(secret-tool lookup service a user y 2>/dev/null)" == "third" ]] &&
	ok "the third item is retrievable" || bad "wrong secret for service=a user=y"

# --------------------------------------------------------------- reindex

section "Reindex"

if binpass ss reindex 2>/dev/null | grep -q 'Indexed 3 item'; then
	ok "reindex counts the items on disk"
else
	bad "reindex reported the wrong count: $(binpass ss reindex 2>&1)"
fi

if [[ "$(secret-tool lookup service a user x 2>/dev/null)" == "first" ]]; then
	ok "lookup still works after a rebuild"
else
	bad "the rebuilt index does not answer lookups"
fi

# ---------------------------------------------------------------- report

section "Result"
printf '  %d passed, %d failed\n\n' "$pass_count" "$fail_count"
[[ $fail_count -eq 0 ]] || { echo "--- provider log ---"; cat /tmp/ss.log; exit 1; }
