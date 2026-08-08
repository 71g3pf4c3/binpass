# Задание: доделать текущую работу (незакоммиченный WIP)

> Вставь перед этим текстом `00-CONTEXT.md`.

Это то, над чем работа шла прямо сейчас. В рабочем дереве **незакоммиченные
изменения**. Начни с `git status` и `git diff`, чтобы увидеть их.

## Контекст: два бага, найденных пользователем

Оба уже исправлены в рабочем дереве, но **требуют проверки и коммита**.

### Баг 1. Буфер обмена на Wayland стирал данные пользователя

`pkg/clip/backends.go` регистрировал бэкенд, у которого чтение буфера
выполнялось бинарём `wl-copy` с пустыми аргументами. То есть `Paste()`
запускал `wl-copy` без stdin и **затирал буфер пользователя** вместо чтения.
Плюс `cmd.Output()` захватывал stdout, который наследует форкнутый демон
`wl-copy`, — процесс висел до замены буфера.

Исправлено: раздельные `bin` (чтение) и `copyBin` (запись); `runCopy()` не
captures stdout; Wayland идёт **раньше** X11 (в Wayland-сессии часто выставлен
и `DISPLAY` через Xwayland, и запись ушла бы в слой совместимости).
Регрессионный тест — `pkg/clip/backends_test.go`.

### Баг 2. `binpass sus` не находил identity, который сам же создал

Резолвер искал ключ в `~/.local/share/binpass/identities.age`, а `init`
исторически писал его в `~/.config/binpass/identities.age`. Пользователь видел
запись в `ls`, но не мог её открыть.

Исправлено: `DefaultFiles()` ищет в обоих местах; ошибка теперь перечисляет
**все** просмотренные пути и подсказывает `age-keygen`. Ключ, созданный самой
программой, обязан быть найден этой же программой.

## Что доделать

### 1. Изолированное окружение — довести до зелёного

`Dockerfile.e2e` + `scripts/e2e-session.sh` поднимают headless sway и Xvfb в
контейнере и гоняют полный набор: буфер обмена на Wayland и X11, launcher-
скрипты, completion, взаимную совместимость с pass.

Последний прогон: **30 passed, 3 failed**. Осталось:

* `Xvfb failed to start` — проверка готовности использовала `xdpyinfo`,
  которого нет в образе. Уже переписано на пробу через `xclip`;
  **перепроверь**.
* Два падения `binpass-fzf path ...` — секция X11-фолбэка делает
  `unset WAYLAND_DISPLAY` и возвращает его в конце, но launcher-секция идёт
  после и, судя по всему, работает не в том окружении, в каком ожидает.
  Разберись: скорее всего порядок секций или область видимости переменной.

Цель — **0 failed**. Запуск:
```sh
docker build -f Dockerfile.e2e -t binpass-e2e . && docker run --rm binpass-e2e
```

**Важно:** ни одна проверка не должна трогать домашний каталог, стор, gpg-
кейринг или буфер обмена разработчика. Только контейнер и временные каталоги.

### 2. Completion — дописать

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

### 3. GitLab CI

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

### 4. Проверить весь набор и закоммитить

```sh
gofmt -l . ; golangci-lint run ; make test ; make cover
docker run --rm binpass-test
docker run --rm binpass-e2e
nix build .#default && nix flake check
nix develop --command goreleaser release --snapshot --clean
```

Коммить логическими частями, не одной кучей: фикс буфера обмена (с описанием,
что именно стирало данные), фикс поиска identity, e2e-окружение, completion,
GitLab CI.

## Ещё не сделано и стоит проверить

* `nfpms` в `.goreleaser.yaml` собирает deb/rpm/apk/archlinux — проверено
  установкой в Debian-контейнере. **winget и AUR из §13 не настроены.**
* `vendorHash` в `flake.nix` прибит гвоздями. При изменении зависимостей его
  надо обновлять — опиши это в README, иначе следующий человек упрётся.
