# Tasks

## 1. Adapter [sequential]

- [ ] 1.1 Add `pkg/sopsfile` (`doc.go`, `sopsfile.go`): `Open(path)` validating the extension and locating `sops`; `decrypt`/`set`/`unset`/`encrypt` exec helpers with secrets on stdin only; the in-memory tree with `/`-path addressing; the `tui.Store` method set (List/Get/Set/Remove/Move/Copy/RemoveDir/IsDir/Grep/Exists/Dir). Verify: `go build ./...` and `go vet ./pkg/sopsfile`.
- [ ] 1.2 Add `pkg/sopsfile/sopsfile_test.go`: table tests against the real `sops` with a generated age key and temp `.sops.yaml` (skip with `sops not on PATH` / `age-keygen not on PATH`); cover listing, slash-key error, newline round-trips (single-line, multi-line, newline-terminated, edit of existing), nested create, remove/removedir, move/copy of key and group, non-string leaves, create-on-first-set, unsupported extension. Verify: `go test ./pkg/sopsfile/`.

## 2. TUI gate [sequential]

- [ ] 2.1 Add `tui.Options.Standalone`; skip VCS detection and guard history/status/attach/extract bindings with a status-bar message. Verify: existing `go test ./internal/tui/` still green.
- [ ] 2.2 Add a model test for Standalone mode asserting the bindings leave the view unchanged and set the status message. Verify: `go test ./internal/tui/ -run Standalone`.

## 3. CLI [sequential]

- [ ] 3.1 Add `internal/cli/sops.go` with `binpass sops edit|ls|get|set|rm` registered in `root.go`; `set` reads stdin verbatim when piped and prompts without echo on a TTY; `rm -r` for groups; `edit` runs the TUI with `Standalone: true`. Verify: `go build ./...` and `binpass sops --help`.
- [ ] 3.2 Add a CLI test over a temp sops file covering ls/get/set/rm, create-on-first-set, missing file lists nothing, unsupported extension, and that `sops decrypt` still reads the result. Verify: `go test ./internal/cli/ -run Sops`.

## 4. Environment and docs [parallel]

- [ ] 4.1 Add `sops` and `age` to the dev shell in `flake.nix`, to `Dockerfile.test`, and to both CI definitions; `make ci-parity` passes. Verify: `nix flake check --no-build`, `make ci-parity`.
- [ ] 4.2 Write `docs/sops.md` (purpose, key resolution is sops's, path mapping, newline rule, write semantics, minimum sops version, Makefile `secrets-edit` example); add README feature line and AGENTS.md layout note. Verify: files present and referenced.

## 5. Integration [sequential]

- [ ] 5.1 Full battery: `go build ./...`, cross-builds (darwin/arm64, windows/amd64, windows/arm64, linux/arm64), `golangci-lint run`, `gofmt -l .` empty, `make test`, `make cover`, `nix flake check --no-build`. Verify: all exit 0.
- [ ] 5.2 Manual smoke in a temp dir: generated key + `.sops.yaml`, `binpass sops set/ls/get/rm` on a fresh file, `sops decrypt` of the result; TUI driven through the model test. Verify: observed output recorded in the final report.

## Workflow follow-up

- `openspec archive add-sops-secrets` after merge into `main`.
