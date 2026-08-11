# Текущий WIP: фиксы, e2e, completion, GitLab CI

> Вставь перед этим текстом `00-CONTEXT.md`.

## Что уже закоммичено (на main)

### Баг 1. Буфер обмена на Wayland стирал данные пользователя ✅

`pkg/clip/backends.go` — раздельные `bin` (чтение) и `copyBin` (запись);
`runCopy()` не captures stdout; Wayland идёт раньше X11.
Регрессионный тест — `pkg/clip/backends_test.go`.

### Баг 2. `binpass sus` не находил identity ✅

`DefaultFiles()` ищет в `~/.local/share/binpass/` и `~/.config/binpass/`;
ошибка перечисляет все просмотренные пути и подсказывает `age-keygen`.

### E2E-окружение ✅

`Dockerfile.e2e` + `scripts/e2e-session.sh`: **43 passed, 0 failed**.
Включает: clipboard (Wayland + X11), launchers, completion, import, audit, binary.

---

## Что ещё не сделано

### 1. Completion — дописать

`internal/cli/completion.go` уже есть: генерация для bash/zsh/fish/powershell и
дополнение имён записей из стора (без расшифровки — важно, иначе токен будет
пищать при каждом Tab).

Осталось:
* Дополнение **флагов со значениями**: `--field=` подставляет реальные имена
  полей записи, `--launcher=` — список пикеров.
* Проверить `mv`/`cp`: у них два аргумента, второй тоже должен дополняться.
* Установка completion в пакеты `.deb`/`.rpm` (`.goreleaser.yaml`, секция
  `nfpms.contents`): bash — в `/usr/share/bash-completion/completions/binpass`,
  zsh — в `/usr/share/zsh/site-functions/_binpass`, fish — в
  `/usr/share/fish/vendor_completions.d/binpass.fish`. Генерируй на этапе
  сборки хуком goreleaser.

### 2. GitLab CI

Просили `.gitlab-ci.yml` с автотестами, линтерами, сборкой релизов и
публикацией артефактов. **Ещё не сделан.** Существующий
`.github/workflows/ci.yml` — образец по составу проверок.

Нужны стадии:
* `lint` — `golangci-lint run`, `gofmt -l`, `go vet`.
* `test` — весь набор. **Обязательно ставь настоящий `pass`, `gnupg`, `tree`**,
  иначе golden-тесты молча пропустятся и ничего не проверят. Добавь явную
  проверку наличия `pass` с `exit 1`, если его нет.
* `test:e2e` — сборка `Dockerfile.e2e` и прогон (нужен docker-in-docker).
* `coverage` — gate ≥70%, с `coverage_report`/`cobertura` для GitLab.
* `build` — матрица linux/darwin/windows × amd64/arm64.
* `release` — goreleaser по тегу, артефакты в GitLab Releases. Учти, что
  goreleaser для GitLab требует `GITLAB_TOKEN` и секцию `gitlab:` в конфиге.

Кешируй `$GOPATH/pkg/mod` между запусками.

### 3. Проверить весь набор

```sh
gofmt -l . ; golangci-lint run ; make test ; make cover
docker run --rm binpass-test
docker run --rm binpass-e2e
nix build .#default && nix flake check
nix develop --command goreleaser release --snapshot --clean
```

## Ещё не сделано и стоит проверить

* `nfpms` в `.goreleaser.yaml` собирает deb/rpm/apk/archlinux — проверено
  установкой в Debian-контейнере. **winget и AUR из §13 не настроены.**
* `vendorHash` в `flake.nix` прибит гвоздями. При изменении зависимостей его
  надо обновлять — опиши это в README, иначе следующий человек упрётся.

## M2 — закрыт на ветке `feat/import-audit`

Коммиты `be56074` (import + audit) и `5a47a31` (binary). Включает:

* `pkg/importer` — 9 форматов, Registry, Plan/WriteEntries, dry-run, export CSV
* `pkg/audit` — HIBP k-anonymity, zxcvbn, reuse, expiry, JSON output
* `pkg/binary` — .b64 entries: Cat, Sum, Store, DetectBinary
* CLI: `binpass import`, `binpass export`, `binpass audit`, `binpass binary`
* E2E: 43 passed, 0 failed

Ветка ещё не влитана в main.
