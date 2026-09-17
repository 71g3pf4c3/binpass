# AGENTS.md

`binpass` — a pass(1)-compatible password manager. Single Go binary, module
`github.com/71g3pf4c3/binpass`, entrypoint `cmd/binpass`. `ARCHITECTURE.md`
is the spec the implementation follows; `docs/agent-tasks/00-CONTEXT.md`
contains the project's hard rules (in Russian) — read it before any
non-trivial change.

## Commands

```sh
nix develop                      # dev shell: go, gopls, golangci-lint, goreleaser, syft,
                                  # plus real pass, gnupg, age, git, tree, qrencode
make test                         # go test ./...   (CGO_ENABLED=0)
make test-race                    # requires cgo — CI runs -race, local plain `make test` doesn't
make cover                        # coverage with business-logic filter, gate is >=70%
make build                        # bin/binpass with -trimpath and ldflags version stamping
golangci-lint run                 # must be 0 issues (v2 config, see .golangci.yml)
gofmt -l .                        # must be empty
```

Single package / single test: `go test ./pkg/sync/ -run TestScan_Basic`.
Fuzz targets (failures are saved as seed corpora under `**/testdata/fuzz/`,
which are permanent regressions — keep them): `./scripts/fuzz.sh 20`.
Container suites: `Dockerfile.test` (plain Debian + distro pass),
`Dockerfile.e2e` (interactive flows), `Dockerfile.ss` (Secret Service over a
real session bus), `Dockerfile.luks` (`--privileged`, dm-crypt).

## Non-obvious constraints

- **Compatibility with pass is enforced by tests, not intent.** The golden
  suite in `internal/cli/golden/` runs the real `pass` and binpass on an
  identical store and compares stdout byte for byte. If `pass` or `tree` is
  missing from the environment, these tests **skip silently and prove
  nothing** — that's why CI installs them explicitly. `tree(1)` renders
  glyphs by locale and colours by `TERM`; the golden listing tests depend on
  this behaviour.
- **Never run tests against the developer's real home.** Not
  `~/.password-store`, not `~/.gnupg`, not the system clipboard. Use
  temp dirs/containers. This is not theoretical: a user's live clipboard was
  wiped once. The dev shell helps by unsetting all `PASSWORD_STORE_*` and
  `BINPASS_*` variables so tests measure the code, not the machine — outside
  the dev shell they can leak in.
- **Do not break `CGO_ENABLED=0`.** External tools (`gpg`, `git`, `cryptsetup`,
  `age-plugin-*`, rclone, restic) are invoked via `exec`, never linked.
- **Nothing app-owned inside the store.** Sync state, caches, indexes live in
  `$XDG_STATE_HOME/binpass/` / `$XDG_DATA_HOME/binpass/`. Inside
  `$PASSWORD_STORE_DIR` only what pass understands, plus `.binpass/plugins/`.
- **Secrets never in argv, logs, or plaintext on disk.** Input from
  TTY/stdin only; temp files 0600 on tmpfs where available
  (`internal/cli/tmpfile.go`).
- **Windows/Unix split** via build tags (`tty_unix.go`/`tty_windows.go`,
  `luks_linux.go`/`luks_other.go`, etc.). CI builds linux/darwin/windows ×
  amd64/arm64 — keep all pairs compiling.

## Conventions

- Godoc on every exported symbol, comments end with a period (`godot`,
  `revive.exported`). Comments explain *why*, not *what*. Test files and
  mocks are exempt from these linters (see `.golangci.yml` exclusions).
- Tests: table-driven, verified against a reference where one exists (real
  pass, RFC vectors, txtar e2e via `go-internal` in `internal/cli/e2e/`).
- Commits: conventional commits, body explains why. `git log -1 a3cf478` is
  the reference example.
- CI exists twice and must stay in sync: `.github/workflows/ci.yml` and
  `.gitlab-ci.yml` (the latter references design decisions in
  `docs/agent-tasks/06-current-wip.md`).
- Nix: `nix flake check --no-build` must pass; format with `nix fmt`
  (nixfmt-rfc-style). After changing Go dependencies, update `vendorHash` in
  `flake.nix`. `docs/agent-tasks/README.md` tracks which task files are done
  vs WIP.

## Layout

`pkg/*` are the business-logic packages (crypto, store, sync, tomb, audit,
importer, secretservice, …) — each with its own tests and `doc.go`.
`internal/cli` is the cobra command surface (one file per command).
`internal/tui` is the bubbletea TUI. `internal/config` is viper-based
config (YAML + env; `BINPASS_*` overrides `PASSWORD_STORE_*`).
`share/` holds systemd/DBus unit files installed by the Nix package.
