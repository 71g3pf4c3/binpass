# Tomb: полная интеграция в binpass

> Соответствует ARCHITECTURE §7. Реализация: `pkg/tomb/`, CLI: `internal/cli/tomb.go`.

## Что делает tomb

Скрывает весь password store целиком, когда он не используется. В состоянии «закрыт» в каталоге стора нет ни имён записей, ни структуры каталогов, ни факта их существования — только один файл `store.coffin.age` и dotfiles (`.age-recipients`, `.gpg-id`, `.git/`).

Это радикальное решение проблемы «провайдер синхронизации видит имена записей» (§8.4, §10): наружу уезжает один blob.

## Архитектура

```
┌──────────────────────────────────────────────────────────┐
│                     binpass tomb open                     │
│                                                          │
│  1. SelectBackend(coffin)                                │
│  2. Coffin.Open(dir, timer)                              │
│     ├── os.Stat(store.coffin.age)          ← coffin есть?│
│     ├── hasPlaintext(dir)                  ← уже открыт?│
│     ├── loadState(dir) → IsStale()         ← crash?     │
│     ├── unpackDecrypt(dir, coffinPath)                   │
│     │   ├── age.Decrypt(f, identities)      ← decrypt    │
│     │   └── readTar(dr, dir)                ← extract    │
│     │       └── isWithin(dir, target)       ← traversal │
│     ├── mlockDir(dir)                       ← anti-swap  │
│     └── saveState(dir, &s)                  ← crash det  │
│                                                          │
│  3. NewWatcher(dir, timer, onClose)                      │
│     ├── timerLoop    → triggerClose()      ← timeout    │
│     ├── sessionBus   → ActiveChanged(true) ← screenlock │
│     └── systemBus    → PrepareForSleep      ← suspend   │
│                                                          │
│  4. <-sigCh (SIGINT/SIGTERM)                             │
│  5. watcher.Stop()                                       │
└──────────────────────────────────────────────────────────┘
```

```
┌──────────────────────────────────────────────────────────┐
│                     binpass tomb close                    │
│                                                          │
│  1. hasPlaintext(dir)                       ← открыт?    │
│  2. readRecipients(dir)                     ← .age-recip│
│  3. packEncrypt(dir, tmpCoffin, rcp)                      │
│     ├── writeTar(&buf, dir)                 ← tar store  │
│     ├── age.Encrypt(f, recipients)           ← encrypt   │
│     ├── f.Sync()                             ← durability│
│     └── os.Rename(tmpCoffin, coffinPath)     ← atomic    │
│  4. shredDir(dir, coffinFileName, stateFileName)          │
│     ├── overwriteRandom(path, size)          ← shred     │
│     └── os.Remove(path)                      ← unlink    │
│  5. os.Remove(statePath(dir))               ← cleanup    │
└──────────────────────────────────────────────────────────┘
```

## Три бэкенда

| Бэкенд | Статус | OS | Root | Защита |
|--------|--------|-----|------|--------|
| **Coffin** | Реализован | Все | Нет | age-encrypted tar. Plaintext в tmpfs на время сессии |
| LUKS | Stub (`ErrNotImplemented`) | Linux | Да (polkit) | dm-crypt. Plaintext только в kernel mapping |
| Sparsebundle | Stub (`ErrNotImplemented`) | macOS | Нет | Encrypted APFS sparse bundle |

Выбор бэкенда — `tomb.SelectBackend(want)` или `tomb.DefaultBackend()`. На всех платформах default = coffin.

### Coffin — детали реализации

**Формат:** `store.coffin.age = age.Encrypt(tar(store_dir/))`

Только `archive/tar` + `filippo.io/age`, оба в-process, без внешних бинарей.

Что попадает в tar:
- Все обычные файлы и подкаталоги store, кроме dotfiles и `store.coffin.age`
- Права доступа каталогов сохраняются
- Symlinks сохраняются как tar symlink headers

Что НЕ попадает в tar (и survives между open/close):
- `.age-recipients` — recipients для re-encryption
- `.gpg-id` — GPG recipients
- `.git/` — git sync
- Все dotfiles и dot-directories

**Почему dotfiles не архивируются:** они должны быть доступны для `readRecipients()` на Close. Если бы `.age-recipients` лежал только внутри coffin, Close не смог бы найти recipients для re-encryption. Это by design, не oversight.

**Atomic write на Close:**
1. `packEncrypt` → временный файл `.writing`
2. `f.Sync()` → durability
3. `os.Rename(tmp, coffinPath)` → atomic swap
4. Старый coffin перезаписан, откат невозможен (но данные уже в новом)

### LUKS — текущее состояние

Constructor проверяет `cryptsetup` на PATH. Init/Open/Close возвращают `ErrNotImplemented`. Тип `LUKS` реализует `Tomb` интерфейс, регистрируется в `SelectBackend("luks")`.

Поля, которые будут нужны при реализации:
- `identities IdentityFunc` — для расшифровки key file
- Key file сам зашифрован age/GPG → аппаратный токен работает из коробки
- `cryptsetup luksOpen/luksClose` вызывается через `os/exec`
- `ErrNeedRoot` возвращается при нехватке привилегий

### Sparsebundle — текущее состояние

Constructor проверяет `hdiutil` на PATH (всегда доступен на macOS). Init/Open/Close возвращают `ErrNotImplemented`.

## CLI: `binpass tomb`

Зарегистрировано в `internal/cli/root.go` как `newTombCmd(app)`.

### `binpass tomb init`

```
binpass tomb init [--type=coffin] [--size=1G] [--recipient=age1...]
```

Создаёт `store.coffin.age` из текущего содержимого store. **Plaintext НЕ удаляется.** Store продолжает работать как обычно. Init — add-only операция: coffin появляется рядом с plaintext.

Если `--recipient` не указан — читает из `.age-recipients` / `.gpg-id` в store. Если recipients не найдены — ошибка.

`--size` зарезервирован для LUKS/sparsebundle. Для coffin игнорируется.

### `binpass tomb open`

```
binpass tomb open [--timer=1h]
```

1. Определяет бэкенд из state file (или default = coffin)
2. Расшифровывает coffin в store directory
3. Пишет state file в sidecar
4. Запускает auto-close watcher
5. **Блокирует** процесс до SIGINT/SIGTERM или auto-close

Процесс должен жить, пока tomb открыт — watcher goroutines требуют running process. Ctrl+C вызывает `watcher.Stop()` и exit.

**`--timer=0` или не указан** — timer отключен, tomb не закроется автоматически. D-Bus screenlock/suspend продолжают работать (Linux).

### `binpass tomb close`

```
binpass tomb close [--force]
```

1. Проверяет `hasPlaintext(dir)` → если нет, `ErrNotOpen`
2. Читает recipients из `.age-recipients` / `.gpg-id`
3. Re-encrypts plaintext в новый coffin (atomic swap)
4. Shreds plaintext (overwriteRandom + os.Remove)
5. Удаляет state file

**`--force`** зарезервирован. В текущей реализации `Coffin.Close(dir, force)` принимает `force`, но не использует — dirty check пока не реализован.

### `binpass tomb status`

```
binpass tomb status
```

Читает state file и показывает:
- `open` / `closed` / `stale (crash without close)` / `not initialised`
- Бэкенд, store path, время открытия, timer, watcher status

## State file

**Путь:** `$XDG_DATA_HOME/binpass/<basename>-tomb.state`

Override: `BINPASS_DATA_DIR` → весь sidecar переезжает.

**Зачем вне store:** git sync и cloud sync не должны видеть device-specific runtime state. Если state file попадёт в git, `binpass tomb status` на другой машине будет показывать чужой PID.

**Схема:**
```json
{
  "backend": "coffin",
  "store_dir": "/home/user/.password-store",
  "coffin_path": "/home/user/.password-store/store.coffin.age",
  "opened_at": "2026-08-09T14:30:00Z",
  "timer": 3600000000000,
  "pid": 12345
}
```

**Stale detection:** `State.IsStale()` → `pidIsDead(PID)` → `syscall.Kill(pid, 0)`. ESRCH = dead, EPERM = alive (other UID), nil = alive. На Windows — conservative: PID считается живым, stale не детектируется.

**Collision:** state filename = `filepath.Base(abs) + "-tomb.state"`. Два store с одинаковым basename на одной машине разделяют state file. Известное ограничение, будет исправлено на hash от полного пути.

## Auto-close watcher

### Linux

```
Watcher
├── timerLoop       time.After(timer)                    → triggerClose()
├── watchSessionBus (D-Bus session bus)
│   ├── org.gnome.ScreenSaver.ActiveChanged(true)        → triggerClose()
│   └── org.freedesktop.ScreenSaver.ActiveChanged(true) → triggerClose()
└── watchSystemBus  (D-Bus system bus)
    └── org.freedesktop.login1.Manager.PrepareForSleep(true) → triggerClose()
```

- `godbus/dbus/v5` — чистый Go, no CGO
- D-Bus недоступен (headless, container) → graceful degradation, timer-only
- `DoctorCheck()` показывает, какие D-Bus сервисы найдены
- `triggerClose()` — single-shot: mutex + `closed` flag, второй вызов no-op

### macOS / Windows

Только timer. Screen lock detection (IOKit, WinAPI) — TODO.

## Интеграция с подсистемами binpass

### pkg/crypto — recipients и identities

**На Open:** `Coffin.unpackDecrypt` вызывает `age.Decrypt(f, identities)`. Identity resolver — тот же, что использует `pkg/crypto/age.Age.Decrypt`: `identity.NewResolver(cfg.Identity).Load()`. Аппаратные токены работают из коробки — age-plugin протокол не меняется.

**На Close:** `Coffin.readRecipients` читает `.age-recipients` или `.gpg-id` из plaintext directory. Парсинг — `crypto.ParseAgeRecipients`, та же функция, что в `Age.Encrypt`. GPG-recipient строки не попадают в coffin — Close использует `.gpg-id` только как fallback, encrypt через age.

**Wire-up в CLI:**
```go
// internal/cli/tomb.go:157
if c, ok := t.(*tomb.Coffin); ok {
    c.SetIdentities(a.identities)  // a.identities → identity.NewResolver
}
```

### pkg/store — store operations при открытом tomb

Tomb open = plaintext directory содержит обычные файлы. `pkg/store` работает поверх этой директории без изменений — `store.Get`, `store.Set`, `store.List` etc. Store не знает, что данные пришли из coffin.

**Важно:** store operations между Open и Close модифицируют plaintext. На Close весь текущий plaintext перешифровывается в coffin. Любые изменения, не сохранённые до auto-close, теряются.

### pkg/storage — dotfiles и iterate rules

`Coffin.writeTar` и `Coffin.shredDir` используют тот же pattern, что `storage.FS`: skip dotfiles (`rel[0] == '.'`). Это гарантирует, что `.age-recipients`, `.gpg-id`, `.git/` переживают close и доступны при следующем open.

`hasPlaintext` тоже следует этому правилу: dotfiles и `store.coffin.age` не считаются plaintext, что позволяет отличить "tomb закрыт" от "tomb открыт".

### internal/config — environment overrides

| Переменная | Влияние на tomb |
|------------|-----------------|
| `BINPASS_DIR` / `PASSWORD_STORE_DIR` | Каталог store (коффины и plaintext здесь) |
| `BINPASS_IDENTITY` | Путь к identity file для age decrypt |
| `BINPASS_DATA_DIR` | Переопределяет каталог state file |
| `XDG_DATA_HOME` | Fallback для state file (если нет BINPASS_DATA_DIR) |

### Взаимодействие с git

- `.git/` — dotfile, переживает close. Commit history не теряется.
- `store.coffin.age` — обычный binary файл, git видит его как blob
- `.age-recipients` — dotfile, не архивируется в coffin, переживает close
- Sync с открытым tomb: plaintext в store dir, git видит и файлы, и coffin
- Sync с закрытым tomb: git видит только coffin + dotfiles
- **Caveat:** если tomb закрыт, `binpass git log` покажет только coffin-commits, не per-entry. Это trade-off: metadata privacy vs. granular history

### Взаимодействие с binpass-agent / Secret Service

Tomb close делает все секреты недоступными. Если `binpass-agent` держит decrypted keys в памяти:
- Secret Service запросы вернут `Locked` (tomb closed → no plaintext)
- `binpass-agent` должен обрабатывать `ErrNotInitialised` / `ErrNotOpen` от tomb
- `binpass-agent forget` может триггерить tomb close (planned)

### Взаимодействие с clipboard

`binpass show -c` при открытом tomb работает как обычно. При закрытом:
- Store dir содержит только coffin + dotfiles
- `binpass show <entry>` → file not found → ошибка
- Не crash, а корректная ошибка: "Error: <entry> is not in the password store."

## Security: что защищено и что нет

### Защищено

| Свойство | Механизм |
|----------|----------|
| Имена записей в покое | Только `store.coffin.age` на диске |
| Структура каталогов в покое | Внутри age-encrypted tar |
| Аутентичность coffin | Age authenticated encryption: tampered ciphertext fails decrypt |
| Double-open | `hasPlaintext` + `loadState` + `IsStale` PID check |
| Crash recovery | State file с PID → `binpass doctor` / следующий Open видит stale |
| Plaintext в swap (Linux) | `mlockDir`: mmap + Mlock для файлов < 64KB |
| Зависший tomb | Auto-close: timer + screenlock + suspend |

### НЕ защищено (by design или limitation)

| Свойство | Причина |
|----------|---------|
| Plaintext во время сессии | Coffin архитектура: plaintext в tmpfs на время Open. LUKS (не реализован) решает это |
| SSD shred | Wear-leveling: `overwriteRandom` не гарантирует физического уничтожения. CLI предупреждает |
| Recipient injection | `.age-recipients` — plaintext dotfile. Если attacker может его модифицировать, Close зашифрует на его recipient. Но attacker с write access к store dir уже имеет plaintext |
| D-Bus spoofing | Любой процесс на session bus может отправить `ActiveChanged(true)`. Impact: nuisance close, не data leak. Threat model: single-user local |
| Concurrent Open | Нет filesystem lock. `O_EXCL` даёт частичную защиту. Unlikely в single-user модели |
| State file collision | `filepath.Base` вместо hash. Два store с одинаковым basename → collision |

### Сравнение с tomb(1) + pass-tomb

| Свойство | binpass coffin | tomb(1) |
|----------|---------------|---------|
| OS | Все | Linux |
| Root | Не нужен | Нужен для LUKS |
| Формат | age-encrypted tar | LUKS container |
| Plaintext в RAM | Да (tmpfs) | Нет (dm-crypt mapping) |
| Аппаратные ключи | Нативно (age-plugin) | Через GPG keyfile |
| Кроссплатформа | Да | Нет |
| Shred гарантии | SSD caveat | SSD caveat (те же) |
| Auto-close | Timer + D-Bus | Timer (в pass-tomb) |

## Known limitations и TODO

| Что | Статус | Приоритет |
|-----|--------|-----------|
| LUKS backend | Stub (`ErrNotImplemented`) | M5+ |
| Sparsebundle backend | Stub (`ErrNotImplemented`) | M5+ |
| `--force` в Close | Параметр принимается, не используется | Low |
| State file collision (filepath.Base) | Известное ограничение | Medium |
| Symlink path traversal в readTar | `isWithin` проверяет logical path, не symlink-resolved path. Динамически подтверждено: symlink + O_EXCL = write outside store. Fix: reject TypeSymlink в readTar | High |
| Streaming packEncrypt | Полный tar в памяти. Для store >100MB — проблема | Medium |
| Identity key zeroization | `age.X25519Identity` не zeroize private key. Go GC handles, но не explicit | Low |
| mlock cleanup (munmap) | mmap'd regions не munmap'ятся до process exit. MAP_SHARED + overwriteRandom инвалидирует mapping, но inode не freed | Low |
| `binpass doctor` | DoctorCheck() реализован, но CLI subcommand не зарегистрирован | Medium |
| Screen lock на macOS/Windows | Только timer | M5 milestone |
| `trimSpace` не обрабатывает `\r` | Windows line endings в `.age-recipients` могут вызывать parse errors | Low |
| `tar.TypeLink` (hardlinks) | Молча пропускаются при extraction | Low |

## Error reference

| Error | Когда | Recovery |
|-------|-------|----------|
| `ErrNotInitialised` | Open, но coffin не существует | `binpass tomb init` сначала |
| `ErrAlreadyOpen` | Open, но plaintext уже есть или живой PID | `binpass tomb close` или `binpass tomb status` |
| `ErrNotOpen` | Close, но plaintext отсутствует | Ничего делать не надо |
| `ErrUnsupported` | Выбран backend не для этой OS | Использовать coffin |
| `ErrNotImplemented` | LUKS/sparsebundle Init/Open/Close | Coffin или ждать реализации |
| `ErrNeedRoot` | LUKS требует root/polkit | Запустить с sudo или настроить polkit |
| `ErrShredWarning` | Close на SSD | Информационное, не блокирует |
| `tomb: no recipients found in store` | Close, но `.age-recipients` и `.gpg-id` пусты или отсутствуют | Добавить recipient перед close |

## Тесты

**Coverage: 71.6% pkg/tomb**

| Файл | Тип | Ключевые сценарии |
|------|-----|-------------------|
| `tomb_test.go` | Unit | SelectBackend, lifecycle, state, shredDir, hasPlaintext, IsStale |
| `coffin_test.go` | Integration | Tar round-trip, path traversal, encrypt/decrypt, overwrite, watcher, crash recovery |
| `e2e_test.go` | E2E | 18 сценариев: full lifecycle, content survival, multiple cycles, double-open, crash recovery, timer, shred, nested dirs, permissions |

Ключевые тесты:
- `TestE2E_FullLifecycle`: init → open → modify → close → open → verify
- `TestE2E_CrashRecovery`: simulate crash (state file left, PID dead) → next Open detects stale → cleanup → proceed
- `TestE2E_TimerAutoClose`: open with timer → wait → tomb auto-closes
- `TestE2E_NoPlaintextAfterClose`: verify directory listing after close
- `TestE2E_ShredOverwritesData`: read file after overwriteRandom, verify not original content
- `TestReadTarPathTraversal`: `../../` in tar header → rejected by isWithin

**Gap:** symlink-based path traversal в readTar не покрыт тестом. Подтверждён отдельным harness. Нужен fix + тест.
