# Задание: доработка синхронизации (post-M4 hardening)

> Вставь перед этим текстом `00-CONTEXT.md`.

Основная функциональность sync (M3+M4) реализована и закоммичена. Это задание —
доделка: атомарность на cloud-транспортах, property-тесты, OAuth, CLI для
restic snapshots. Критический путь пройден, здесь — production hardening.

## Что уже работает

- `pkg/sync`: merge engine, version vectors, blake3 scanning, bbolt state.db,
  fsck (83.9% coverage)
- `pkg/remote`: git (Pull/Push/conditional write), restic (snapshots/dedup),
  rclone (S3/Drive/Yandex/WebDAV), stub (65.8% coverage)
- `internal/cli`: sync, remote add/remove/list, conflicts list|diff|resolve, fsck
- Документация: `docs/sync-remotes.md`, `docs/CHANGELOG-sync.md`

## Что доделать

### 1. S3 conditional write через `If-Match` на ETag

**Проблема:** RcloneRemote conditional write сейчас — read-before-write. Race
window между Get (проверка rev) и Put (загрузка). Два клиента, параллельный
Push на S3 → один затрёт другой молча.

**Решение:**
- Rclone не поддерживает `If-Match` напрямую. Два варианта:
  a) Для S3-ремоутов — отдельный `S3Remote` через `minio-go` (или `aws-sdk-go-v2`),
     который нативно делает `PutObject` с `If-Match: <ETag>`. Caps.Atomic = true.
  b) Оставить rclone, но добавить verify-after-write: после `rcat` прочитать
     файл обратно и сравнить хеш. Если не совпадает → delete + вернуть ошибку.
     Это не atomic, но ловит race post-factum.

Вариант (a) — правильный. Если не хочется тянуть SDK — минимум (b), но это
half-measure.

**DoD:** `TestS3Remote_ConditionalWrite` — два клиента, параллельный Put на один
файл, один получает ошибку. Caps().Atomic = true для S3.

### 2. Property-тесты merge engine

**Проблема:** merge покрыт детерминированными cases (merge_test.go, 485 строк).
Нет проверки инвариантов при произвольных входах. spec §12 прямо требует.

**Инварианты:**
1. **Nothing is lost.** Для любых (local, remote, base) каждый файл, который
   есть хотя бы в одном из (local, remote), присутствует в результате — либо
   как ActionPush/Pull/None, либо как ActionConflict (обе копии сохранены).
2. **Merge is commutative.** `Merge(local, remote, base, opener)` и
   `Merge(remote, local, base, opener)` должны давать одинаковый набор действий
   (direction может отличаться, но Conflict и None — совпадают).
3. **VV always advances.** Для каждого Action результат содержит VersionVector,
   где каждый counter ≥ max(local, remote).
4. **Delete vs edit: edit wins.** Если один deleted, другой edited → ActionPush
   или ActionPull (edit), не ActionDelete.
5. **Identical ciphertext: no conflict.** Если local.Hash == remote.Hash,
   non-empty base → ActionNone с merged VV.

**Инструмент:** `testing/quick` или `gopter`. Генерировать случайные Snapshot
(5–20 файлов, 2–4 devices, random VersionVectors, random hash/size), запускать
Merge, проверять инварианты. 10k итераций за секунду.

**DoD:** `pkg/sync/merge_prop_test.go` — 5 инвариантов, проходит `go test
-run TestMergeProperty -count=1000`.

### 3. Advisory locking для Drive/WebDAV

**Проблема:** `RcloneRemote.Lock()` → `NoopUnlock`. Два клиента могут
параллельно писать на Drive/WebDAV → last-write-wins → потеря данных.

**Решение:** `.binpass.lock` файл в корне remote с содержимым:
```
device:thinkpad
ts:2026-08-09T14:22:33Z
ttl:300
```
- `Lock()`: write lock file, read back, если lock stale (ts + ttl < now) →
  steal. Если lock живой и не наш → error.
- `Unlock()`: delete lock file (conditional delete по содержимому).
- `Caps().Locking = true` для Drive/WebDAV/Yandex.

**DoD:** `TestRcloneRemote_AdvisoryLock` — два клиента, один lock, второй
получает ошибку. Lock expire → второй может lock.

### 4. OAuth flow для gdrive/yandex

**Проблема:** сейчас `binpass remote add gdrive` требует `rclone config`
вручную. Пользователь должен сам настроить OAuth token.

**Решение:**
- `binpass remote add gdrive` → поднять HTTP server на `127.0.0.1:port`,
  открыть браузер на OAuth URL, дождаться callback, сохранить token в
  rclone.conf (или в binpass config).
- Headless (`!isatty`): device flow — вывести URL + code, пользователь
  авторизуется на другом устройстве.
- Существующий `~/.config/rclone/rclone.conf` подхватывается без доп. шагов.

**DoD:** `binpass remote add gdrive mydrive` → browser opens → token saved →
`binpass sync --remote=mydrive` работает без ручного rclone config.

### 5. `binpass sync history` — просмотр restic snapshots

**Проблема:** `ResticRemote.Snapshots()` и `Restore()` есть в API, но нет CLI
wrapper. Пользователь не может просмотреть историю snapshots или откатиться.

**Решение:**
```
binpass sync history                    # список snapshots (ID, time, tags)
binpass sync history --remote=backup    # конкретный remote
binpass sync history --diff=abc123..def456  # diff между snapshots
binpass sync restore abc12345           # восстановить snapshot в стор
```

`sync history` вызывает `rem.Snapshots()` для restic, для git — `git log
--oneline` через GitRemote (уже есть `gitLog()` helper).

**DoD:** `binpass sync history` показывает список snapshots. `binpass sync
restore <id>` восстанавливает. Для git — `git log` output.

### 6. Restic snapshot tagging по device

**Проблема:** все restic snapshots идут с `--tag binpass`. В multi-client
сценарии нельзя понять, кто когда пушнил.

**Решение:** `Push()` добавляет `--tag device:<hostname>`:
```
restic backup <store> --tag binpass --tag device:thinkpad
```

DeviceID уже есть в StateDB. `Snapshots()` фильтрует по тегу.

**DoD:** `TestResticRemote_DeviceTag` — Push, Snapshots, verify
`device:<name>` in tags.

### 7. Cloud integration tests через testcontainers

**Проблема:** rclone-based transports (S3, Drive, Yandex, WebDAV) покрыты 0%.
Нет проверки что sync engine работает end-to-end через cloud transport.

**Решение:**
- MinIO через `testcontainers-go` → `TestS3Sync_E2E`
- `rclone serve webdav` как заглушка → `TestWebDAVSync_E2E`
- Сценарий: два MemRemote (или два RcloneRemote на разные prefix), offline
  edits, sync, conflict detection.

**DoD:** `go test -run TestS3Sync_E2E` — green в CI. MinIO container
поднимается, sync гоняет данные, conflict детектится.

## Приоритеты

| # | Задача | Риск без неё | Сложность |
|---|---|---|---|
| 1 | S3 conditional write | data loss при concurrent writes | средняя |
| 2 | Property-тесты merge | скрытый баг в merge logic | низкая |
| 3 | Advisory locking | data loss на Drive/WebDAV | средняя |
| 4 | OAuth flow | UX blocker для gdrive/yandex | высокая |
| 5 | sync history | нет отката при ошибке | низкая |
| 6 | Restic device tagging | debug difficulty в multi-client | тривиальная |
| 7 | Cloud integration tests | untested critical path | средняя |

#1 и #3 — safety, без них production sync на cloud = risk. #2 — confidence в
merge. #4 — UX. #5–7 — completeness.

## Сознательно не делаем

- **`sync.auto: on-change` (fsnotify).** Решено: не нужен. Sync — manual или
  cron, не event-driven.
- **rclone как библиотека (build-tag `rclone_full`).** Сейчас rclone —
  внешний binary (как git, restic). Импорт rclone как library раздувает binary
  на 50+ MB и ломает `CGO_ENABLED=0`. Если понадобится — отдельное задание.
