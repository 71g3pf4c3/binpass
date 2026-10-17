# Design: sops secrets-file support

## Context

`internal/tui.Model` talks to its backend through the `tui.Store` interface
(List/Get/Set/Remove/Move/Copy/RemoveDir/IsDir/Grep/Exists/Dir). A sops
document is a nested map; mapping `/`-separated names onto nesting gives the
TUI a tree without changes to the TUI's own logic. The CLI command group
pattern (`binpass tomb|ss|keychain`) is reused.

## Decisions

### Exec `sops`, never link it

`github.com/getsops/sops/v3` pulls the AWS, GCP, Azure and Vault SDKs and
would need a `vendorHash` bump. AGENTS.md already mandates exec for external
tools. Three invocations are used, all verified against sops 3.13.3:

| operation | command | stdin |
|---|---|---|
| read | `sops decrypt --output-type json FILE` | — |
| write key | `sops set --value-stdin FILE '["a"]["b"]'` | JSON-encoded value |
| delete | `sops unset FILE '["a"]["b"]'` | — |
| create file | `sops encrypt --filename-override FILE --input-type json --output-type yaml\|json` | JSON document |

`set` creates missing intermediate maps; `unset` of the last key leaves an
empty map, which the adapter hides from listings. Secrets travel over stdin
only; argv carries the key path. The decrypted document is cached in memory
and dropped after every write, so the next read reflects what sops wrote.

### Newline fidelity

`secret.New` always terminates the password line with `\n`; sops-nix
consumers often compare tokens byte for byte. Rule on `Set`:

- existing string leaf: keep the original's newline termination (strip one
  trailing `\n` iff the original had none);
- new leaf: a single-line value is stored without its trailing `\n`,
  a multi-line value verbatim.

`get`/`show` print the value verbatim. `sops set` from a pipe stores stdin
verbatim; from a TTY the prompted line is stored without newline.

### Non-string leaves

Numbers, booleans, lists are listed and displayed as their JSON text;
setting them writes a string. Keys containing `/` cannot be addressed and
produce an error naming the key.

### TUI gate

`tui.Options.Standalone` skips VCS detection and makes the history, status
and attach/extract bindings report "not available for this store". No other
TUI path depends on the backend being a directory.

### Creating a new file

Only `Set` can create the file, from a one-key document. `--filename-override`
makes sops apply `.sops.yaml` creation_rules as if the file existed, so new
files pick up the project's master keys without binpass knowing them. Output
is written to a 0600 temp file in the target directory and renamed over.

## Risks

- `sops set` on a value whose parent is a scalar would replace the scalar;
  the adapter rejects that before calling sops.
- sops versions older than `set --value-stdin` (3.10) fail with sops's own
  usage error; documented minimum version.
