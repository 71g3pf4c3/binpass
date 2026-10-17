# Proposal: sops secrets-file support

## Why

NixOS users keep machine secrets in sops-encrypted YAML/JSON files managed by
sops-nix. Editing them today means `sops edit` dropping into `$EDITOR` on the
whole plaintext document; there is no way to browse, group, rename or add
keys interactively, and no scriptable per-key access that keeps the secret
out of argv. binpass already has a TUI and CLI for exactly those operations
over a tree of secrets — only the storage backend differs.

## What Changes

- New command group `binpass sops` operating on one sops-encrypted file:
  - `binpass sops edit FILE` opens the existing binpass TUI over the file's
    keys (browse, search, add, edit, rename/regroup, delete, copy).
  - `binpass sops ls FILE [PREFIX]`, `get FILE KEY`, `set FILE KEY`
    (value from stdin or TTY prompt), `rm FILE KEY [-r]`.
- Nested maps are groups; a key is addressed as `group/sub/key`, which is
  the same addressing sops-nix uses for nested secrets.
- All cryptography stays in the `sops` binary (exec, never linked). Key
  resolution is sops's own (`SOPS_AGE_KEY_FILE`, `~/.config/sops/age/keys.txt`,
  gpg, …); binpass never reads or holds a sops master key.
- Edits to an existing file go through `sops set`/`sops unset`, so the data
  key, the master-key set and unrelated values are untouched and the git diff
  covers only the changed key. A file that does not exist yet is created from
  the first key via `sops encrypt`, honouring `.sops.yaml` creation_rules.
- The TUI gains one option that disables the git-directory features
  (history, status, attachments) for stores that are a single document.

## Capabilities

### New Capabilities

- `sops-secrets`: browsing and editing keys of a sops-encrypted document
  through the CLI and the TUI.

### Modified Capabilities

(none — no existing spec files in this project.)

## Impact

- New package `pkg/sopsfile` (sops exec wrapper + store-like adapter).
- New `internal/cli/sops.go`; one new field in `internal/tui.Options` and
  guards at the git/attachment key bindings.
- `sops` and `age-keygen` become test-time tools: dev shell (`flake.nix`),
  `Dockerfile.test`, both CI definitions. Tests skip with a named reason
  when they are absent, as the golden suite does for `pass`.
- Docs: `docs/sops.md`, README feature list, AGENTS.md layout note.
- No change to the pass-compatible store, its on-disk format, or
  `CGO_ENABLED=0`.

## Non-goals

- Importing sops files into the password store or exporting the store to
  sops format.
- Managing `.sops.yaml`, master keys, `sops updatekeys` or key rotation.
- Preserving YAML comments on keys that binpass rewrites (sops's own
  behaviour applies).
- dotenv/ini/binary sops formats.
