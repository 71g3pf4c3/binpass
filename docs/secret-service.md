# binpass as the system keyring

Chrome, VS Code, NetworkManager, Evolution, GNOME Online Accounts and a long
tail of other programs keep their secrets in the system keyring rather than
asking you. On Linux that keyring is a D-Bus interface,
`org.freedesktop.secrets`, usually served by gnome-keyring. On KDE it is
served by a bridge in front of KWallet, if one is installed at all.

`binpass ss` serves it from your password store instead. Nothing on the
client side changes: the programs go on calling the keyring, and the secrets
land in the store you already back up, sync and hold the keys to.

```sh
binpass ss doctor     # who owns the keyring right now
binpass ss serve      # serve it from the password store
```

> Implements [ARCHITECTURE.md](../ARCHITECTURE.md) §6.1–6.4. Code lives in
> `pkg/secretservice/`, the command in `internal/cli/ss.go`.
>
> **Linux only.** The API is a freedesktop D-Bus interface; macOS and Windows
> have their own keystores, which binpass integrates with rather than
> replaces.

---

## Contents

1. [What it gets you](#1-what-it-gets-you)
2. [Getting started](#2-getting-started)
3. [Replacing gnome-keyring or KWallet](#3-replacing-gnome-keyring-or-kwallet)
4. [How items are stored](#4-how-items-are-stored)
5. [Why the attributes are hidden](#5-why-the-attributes-are-hidden)
6. [Access policy](#6-access-policy)
7. [Running it as a service](#7-running-it-as-a-service)
8. [What is protected, and what is not](#8-what-is-protected-and-what-is-not)
9. [Troubleshooting](#9-troubleshooting)

---

## 1. What it gets you

* **One place for secrets.** What Chrome stores is in the same store as what
  you typed into `binpass insert`, encrypted to the same keys, synchronised
  by the same `binpass sync`.
* **Your keys, including hardware ones.** The keyring inherits whatever
  unlocks the store: an age identity file, a YubiKey, an age plugin.
* **Readable by hand.** An item a browser wrote is an ordinary pass entry.
  `binpass show` and `pass show` read it, `binpass rm` deletes it.
* **Attributes stay private.** The one thing every other implementation
  leaks — which hosts and usernames you have accounts for — stays inside the
  ciphertext. See [§5](#5-why-the-attributes-are-hidden).

---

## 2. Getting started

Check what owns the keyring now:

```sh
binpass ss doctor
# org.freedesktop.secrets: owned by /usr/bin/gnome-keyring-daemon (pid 2317)
```

Only one program can hold that name, so gnome-keyring has to stop taking it
before binpass can have it — see [§3](#3-replacing-gnome-keyring-or-kwallet).
Once it is free:

```sh
binpass ss serve
# Serving org.freedesktop.secrets on the session bus. Press Ctrl-C to stop.
```

In another terminal, with the standard client:

```sh
printf 'correct-horse-battery-staple' |
  secret-tool store --label='GitHub token' server github.com username alice

secret-tool lookup server github.com username alice
# correct-horse-battery-staple
```

And the same item, from the store's side:

```sh
binpass ls secret-service
binpass show secret-service/login/4f3c…
# correct-horse-battery-staple
# label: GitHub token
# attr.server: github.com
# attr.username: alice
# created: 1786464000
```

---

## 3. Replacing gnome-keyring or KWallet

`binpass ss doctor` prints the commands for whichever is in the way:

```sh
systemctl --user mask gnome-keyring-daemon.socket
systemctl --user stop gnome-keyring-daemon.service
```

**KDE is usually not in the way at all.** KWallet does not own
`org.freedesktop.secrets`: `kwalletd6` publishes `org.kde.kwalletd6` and
nothing else, so a plain KDE session leaves the name free and `binpass ss
serve` simply starts. What claims it, when anything does, is a separate
bridge — `ksecretd`, or a distribution package wiring KWallet to the
freedesktop API. `binpass ss doctor` reads the actual owner rather than
guessing, so trust what it prints over any of this.

If a bridge is there, stop that, not KWallet itself:

```sh
systemctl --user mask ksecretd.service     # whatever doctor named
```

Masking `plasma-kwallet-pam.service` disables KWallet's unlock at login,
which is unrelated to the bus name and will annoy you without freeing
anything.

Then log out and back in, or start binpass by hand.

**Existing secrets do not move by themselves.** Whatever is in gnome-keyring
stays there; masking it makes those secrets unreachable until you migrate
them. Export what you need before masking anything — with gnome-keyring
still running, `secret-tool search --all` lists what it holds.

To take the name for one session without disabling anything:

```sh
binpass ss serve --takeover=replace
```

That is useful for trying it out. It is not a way to run both: two providers
taking turns means secrets stored in one and looked up in the other.

---

## 4. How items are stored

Everything lives under `secret-service/` in the store:

```
~/.password-store/
  secret-service/
    .index.age                  encrypted attribute index
    login/
      4f3c9a2b….age             one item
```

An item is an ordinary pass entry: the secret on the first line, then
fields.

```
correct-horse-battery-staple
label: GitHub token
attr.server: github.com
attr.username: alice
created: 1786464000
modified: 1786464000
```

The file name is random rather than derived from the label or the
attributes. It is the one part of an item that stays visible to whatever the
store is synchronised with, so it carries nothing.

Collections map to directories. `login` is the default, because that is what
gnome-keyring calls its own and what programs hardcode when they hardcode
anything.

---

## 5. Why the attributes are hidden

A Secret Service item is a secret plus attributes: `server`, `username`,
`application`, `uri`. Those attributes are a complete map of your accounts.

`pass-secret-service` stores them in plaintext beside the ciphertext — its
README says so outright. The consequence is easy to miss: the passwords are
encrypted, but the list of every service you have an account with, and under
what name, is sitting in the clear in whatever git host or cloud drive the
store syncs to.

binpass puts the attributes inside the encrypted file and keeps a separate
index for lookup:

```
.index.age:  { "MZXW6YTBOI======": ["4f3c9a2b…"], … }
```

Each key is `base32(HMAC-SHA256(index_key, name || 0x00 || value))`. The
index key is derived from the store's recipients and never leaves the
machine.

This works because of a property of the specification: **`SearchItems`
matches attribute pairs exactly**, never by prefix or substring. A search for
`server=github.com` matches only that exact value, which a keyed hash can
answer perfectly. The index is not a compromise on searching; it is the same
search, over hashes.

What still leaks: two items carrying the same attribute value have the same
hash, so an observer learns that some items share *something*. That is a
great deal less than a list of your accounts.

`binpass ss reindex` rebuilds the index from the items. Run it after a sync
brings items in from another machine, or if lookups stop finding things that
`binpass ls` shows.

---

## 6. Access policy

The weak point of the Secret Service model is not this implementation: the
session bus does not isolate applications. Any process running as you can
ask the keyring for any secret. gnome-keyring does not restrict this at all.

binpass can apply a policy before handing anything over.
`~/.config/binpass/secret-service.yaml`:

```yaml
default: allow            # allow | deny | prompt
remember: 8h              # how long a prompt answer is honoured
audit: true               # keep a log of what was read
notify: off               # off | on-access

rules:
  - app: /usr/bin/git
    attrs: { server: github.com }
    action: allow

  - app: "*"
    attrs: { application: ssh }
    action: deny
```

Rules are tried in order and the first match wins. `app` matches the caller's
executable, `*` matches anything; `attrs` matches item attributes, with `*`
as a value meaning "carries this attribute at all".

The caller is identified by asking the bus for the sender's PID and reading
`/proc/PID/exe`. **Be clear about what that proves**: it names the file a
process started from. A process that re-executed itself, or one whose PID
was reused, can misrepresent it. The policy protects against careless and
accidental access, not against a local attacker who is trying. Nothing
stronger is available within the D-Bus model.

`prompt` is **not yet implemented**: there is no UI to ask through, and the
provider runs as a background service. A rule with `action: prompt` currently
denies unless a decision was remembered, on the reasoning that treating "ask
the user" as "yes" would turn the strictest setting into the weakest. Use
explicit `allow` rules until it lands.

---

## 7. Running it as a service

The package ships a user unit and a D-Bus activation file, so the bus can
start the provider on demand when a program asks for the keyring.

With home-manager:

```nix
programs.binpass = {
  enable = true;
  secretService.enable = true;
};
```

By hand:

```sh
systemctl --user enable --now binpass-ss.service
systemctl --user status binpass-ss.service
```

The unit declares `Conflicts=gnome-keyring-daemon.service` rather than
ordering itself after it: only one of the two can own the name, so they must
not both run.

---

## 8. What is protected, and what is not

### Protected

* **Secrets at rest**, by the store's own encryption, with whatever key
  unlocks it.
* **Attribute names and values**, which every other implementation leaks.
  See [§5](#5-why-the-attributes-are-hidden).
* **Secrets in transit over the bus**, when the client negotiates
  `dh-ietf1024-sha256-aes128-cbc-pkcs7`. libsecret does by default.

### Not protected

* **Any process running as you can ask.** That is the model, not a bug here.
  The policy in [§6](#6-access-policy) is a guard rail on top of it.
* **The transport key is 1024-bit DH.** That is what the specification
  names, and a client asking for it will not accept anything stronger. It
  matters less than it sounds: the traffic is between two processes of one
  user over a socket only that user can open.
* **A locked store is not served.** The provider needs to decrypt items, so
  it needs the identity. With a hardware token, that means the token.
* **The index reveals equality.** Two items with the same attribute value
  produce the same hash.

---

## 9. Troubleshooting

### `org.freedesktop.secrets is already owned`

Something else is the keyring. `binpass ss doctor` names the executable and
its PID, which is the answer — on GNOME it is gnome-keyring-daemon, on KDE it
is a bridge rather than KWallet itself. See
[§3](#3-replacing-gnome-keyring-or-kwallet).

### `secret-tool` hangs or reports no such interface

Nothing owns the name at all: the provider is not running, or it is running
against a different session bus. Check that `DBUS_SESSION_BUS_ADDRESS` is the
same in both terminals:

```sh
echo "$DBUS_SESSION_BUS_ADDRESS"
binpass ss doctor
```

### Lookups find nothing, but `binpass ls secret-service` shows items

The index has drifted from the store — most often after a sync brought items
in from another machine:

```sh
binpass ss reindex
# Indexed 12 item(s).
```

### `ss: the store has no recipients`

The index key is derived from them, so the store has to be initialised
first:

```sh
binpass init --age age1...
```

### A program stores secrets but cannot read them back

Check the policy: a `deny` or an unanswered `prompt` refuses the read while
allowing the write, since only reads pass through the policy. `audit: true`
plus the service log shows what was refused and to whom.

### Flatpak and Snap applications

Those go through `org.freedesktop.portal.Secret` rather than talking to the
bus name directly. The portal proxies to whichever provider owns the name,
so binpass serves them too, provided `xdg-desktop-portal` is installed and
running.
