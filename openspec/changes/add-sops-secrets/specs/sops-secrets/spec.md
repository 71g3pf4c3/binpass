# sops-secrets

## ADDED Requirements

### Requirement: Key addressing

The system SHALL expose the keys of a sops-encrypted YAML or JSON document as
a tree in which nested maps are groups and a key is named by joining its map
path with `/`. Keys whose own name contains `/` SHALL be reported as an error
naming the key rather than silently remapped.

#### Scenario: nested key listed by path

- WHEN a document contains `{db: {password: x}, token: y}`
- THEN `binpass sops ls FILE` prints `db/password` and `token`

#### Scenario: key with slash rejected

- WHEN a document contains a map key whose name includes `/`
- THEN listing fails with an error that names that key

### Requirement: Values round-trip byte for byte

The system SHALL return a key's value exactly as stored, and SHALL write back
a value so that single-line values keep no trailing newline, multi-line
values keep theirs, and an existing value keeps its original newline
termination after an edit.

#### Scenario: single-line token stays unterminated

- WHEN `tok` is set as a new value and then read back
- THEN the value is `tok` with no trailing newline

#### Scenario: newline-terminated key material preserved

- WHEN a multi-line value ending in `\n` is set and then read back
- THEN the value is identical, including the trailing newline

#### Scenario: edit keeps original termination

- WHEN an existing value without trailing newline is replaced through the TUI editor
- THEN the stored value has no trailing newline

### Requirement: Secrets never in argv

The system SHALL pass secret values to and from `sops` only through pipes
and SHALL never place a value in a command-line argument.

#### Scenario: set via pipe

- WHEN `binpass sops set FILE KEY` runs with stdin not a terminal
- THEN the value is read from stdin verbatim and the `sops` process receives it on its stdin

#### Scenario: set via terminal

- WHEN `binpass sops set FILE KEY` runs with stdin a terminal
- THEN the value is prompted for without echo and stored without a trailing newline

### Requirement: Edits touch only the changed key

The system SHALL persist a key change to an existing file in a way that
leaves the file's data key, master keys and every other key unchanged.

#### Scenario: other keys untouched

- WHEN one key is set in a file holding several keys
- THEN decrypting the file afterwards with `sops` yields the other keys unchanged and the `sops` metadata still lists the same master keys

#### Scenario: deleting a key

- WHEN `binpass sops rm FILE KEY` is run for an existing key
- THEN the key is absent after the command and the other keys remain decryptable

#### Scenario: deleting a group

- WHEN `binpass sops rm -r FILE GROUP` is run for an existing group
- THEN every key under GROUP is absent afterwards

### Requirement: Creating a new file

The system SHALL create a file that does not exist yet from the first key
written to it, using the project's `.sops.yaml` creation rules for the
target path.

#### Scenario: first set creates file

- WHEN `binpass sops set FILE KEY` is run and FILE does not exist but a creation rule matches FILE
- THEN FILE is created, is decryptable by `sops`, and contains exactly KEY

#### Scenario: listing a missing file

- WHEN `binpass sops ls FILE` is run and FILE does not exist
- THEN the command prints nothing and exits 0

### Requirement: Key material belongs to sops

The system SHALL NOT read, store or prompt for sops master keys; decryption
and encryption SHALL use whatever identity the `sops` binary resolves from
its own environment and configuration.

#### Scenario: identity from environment

- WHEN `SOPS_AGE_KEY_FILE` points at an age identity able to decrypt FILE
- THEN `binpass sops get FILE KEY` succeeds without any binpass-specific key configuration

#### Scenario: sops missing

- WHEN the `sops` binary is not on PATH
- THEN every `binpass sops` subcommand fails with an error stating that sops is not on PATH

### Requirement: Interactive editing

`binpass sops edit FILE` SHALL open the binpass TUI over the file so the
user can browse, search, add, edit, rename or regroup, delete and copy keys,
and SHALL disable features that assume a git-backed directory store.

#### Scenario: TUI over sops file

- WHEN `binpass sops edit FILE` is run in a terminal
- THEN the tree view shows the document's groups and keys and a key opened in the TUI shows its value

#### Scenario: git features unavailable

- WHEN the history, status or attach binding is pressed in the sops TUI
- THEN the status bar reports the feature is not available for this store and no view change occurs

#### Scenario: regroup by rename

- WHEN a key `a/x` is renamed to `b/x` in the TUI
- THEN the document afterwards has `b/x` with the original value and no `a/x`

### Requirement: Supported formats

The system SHALL accept files ending in `.yaml`, `.yml` or `.json` and SHALL
reject any other extension with an error.

#### Scenario: unsupported extension

- WHEN a `binpass sops` subcommand is given `secrets.env`
- THEN it fails with an error naming the supported extensions
