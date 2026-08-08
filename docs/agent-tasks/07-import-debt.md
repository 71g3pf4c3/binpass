# M2: debt, gaps, improvements

> Вставь перед этим текстом `00-CONTEXT.md`.

Сделано — в `04-import-export-audit.md`. Здесь — что осталось доделать, что можно
улучшить, и что сломано. Приоритет: что блокирует production, что — polish.

---

## 1. Блокеры для production merge

### 1.1. Ветка `feat/import-audit` не влита в main

4 коммита + 1 docs commit на ветке. Пока не влито — не существует.

**Действие:** rebase на main, resolve conflicts (если CI добавили), merge.

### 1.2. `runImport`/`runExport`/`runAudit` — 0% unit coverage

`internal/cli/import.go` и `internal/cli/audit.go` содержат `runImport`,
`runExport`, `runAudit`. Эти функции ходят в `app.requireStore()` → реальный
store. Без injection point для mock store — untestable в unit tests.

**Проблема:** если `--format=kaboom` или `--encoding=windows-1251` сломается
после merge — узнаем только из e2e или production.

**Решение:** вынести store interaction в interface:
```go
type importRunner struct {
    store   storeProvider
    opener  fileOpener
    secret  secretReader
}
type storeProvider interface {
    List(sub string) ([]string, error)
    Get(name string) (*secret.Secret, error)
    Set(name string, sec *secret.Secret) error
    Exists(name string) bool
}
```
Тогда `runImport` тестируется с mock store. **Оценка:** ~2 часа.

### 1.3. `internal/cli/binary.go` — тот же 0% coverage

`runBinaryCat`/`runBinarySum`/`runBinaryCopy`/`runBinaryMove` — тот же pattern.
Требуют mock store. Дыра в coverage.

---

## 2. Функциональные gaps

### 2.1. UTF-16 BE не работает в csvReadAll

`stripBOM` снимает 2-байтный BOM, но оставляет null-padded bytes. CSV parser
видит `0x00 a 0x00 ,` и не парсит. UTF-16 LE работает потому что после BOM
strip оставшиеся bytes ≈ ASCII.

**Решение:** добавить `golang.org/x/text/encoding/unicode` decoder для UTF-16
после BOM detection, до CSV parse. Отличать LE от BE по BOM.

**Код:**
```go
if bytes.HasPrefix(raw, []byte{0xFE, 0xFF}) {
    raw = transcodeUTF16BE(raw[2:]) // full decode to UTF-8
}
if bytes.HasPrefix(raw, []byte{0xFF, 0xFE}) {
    raw = transcodeUTF16LE(raw[2:])
}
```

**Оценка:** 30 минут. Низкий приоритет: UTF-16 BE в реальных экспортах
почти не встречается.

### 2.2. Export — sec.Body() в notes

`runExport` кладёт `sec.Body()` (включая `username: alice\nurl: ...`) в
notes-колонку. При re-import получается дублирование: username и URL уже в
отдельных колонках, а в notes — весь body.

**Решение:** извлекать из body только "free-form" строки (не `key: value`, не
`otpauth://`). Либо добавлять отдельную `notes` колонку, не весь body.

**Оценка:** 1 час.

### 2.3. Pass/gopass importer не расшифровывает

Копирует ciphertext как attachment. Для re-encrypt нужен source store's crypto
backend. Пользователь видит attachment с `.gpg` или `.age` расширением, но не
может им пользоваться без ручной расшифровки.

**Решение:** для pass importer — расшифровывать через `store.Get` если source
store доступен. Для gopass — аналогично. Но это требует, чтобы importer знал
о crypto backend source store. Не тривиально.

**Оценка:** 4 часа. Низкий приоритет: edge case.

### 2.4. HIBP persistent cache

Сейчас — in-memory per-run. При audit на 1000+ entries с hardware token —
каждый run заново делает N API calls. Disk cache (between runs) сократит
количество calls.

**Решение:** `$XDG_CACHE_HOME/binpass/hibp/` с SHA-1 prefix → response mapping.
TTL = 24h. Invalidated при HIBP error.

**Оценка:** 2 часа.

### 2.5. Incremental / partial audit

`binpass audit` расшифровывает весь стор. С hardware token — N касаний.
`binpass audit --entries=bank/tinkoff,github/alice` — частичный audit.

**Решение:** filter по entry names/glob после List, до decrypt.

**Оценка:** 1 час.

---

## 3. Coverage improvements

### 3.1. pkg/binary: 85.7% → 90%+

Слабые места:

| Функция | % | Gap |
|---|---|---|
| `encodeB64` | 62.5 | error path (writer fails) не покрыт |
| `HashReader` | 75 | error path (read fails) не покрыт |
| `StoreAndHash` | 80 | `IsBinary` reject branch (уже покрыт в Store, но StoreAndHash — отдельная функция) |

**Оценка:** 30 минут.

### 3.2. pkg/importer: 93% → 95%+

Слабые места (< 85%):

| Функция | % | Gap |
|---|---|---|
| `kdbx.go:Import` | 80 | nil Content/Root — dead code (gokeepasslib заполняет на Decode) |
| `export.go:WriteEntries` | 87 | attachment Set error при force write |
| `chrome.go:Import` | 85 | headerIdx >= len(rows) |
| CSV importers | 83–85 | csvReadAll error path через каждый importer — дублирующий coverage |

**Что реально поднимет coverage:** mock store для CLI functions (п.1.2).
Это даёт +30% на `internal/cli` и попутно тестирует importer/audit/binary через
integration, а не только через unit.

**Оценка:** 2 часа (mock store) + 1 час (tests).

### 3.3. pkg/audit: fetchRange error branch

`fetchRange` делает `http.NewRequestWithContext`. Error на этом этапе не
покрыт (нужен mock http transport или context cancel). 96.2% → 97% при фиксации.

**Оценка:** 30 минут.

---

## 4. Architectural improvements

### 4.1. Импорт: pipeline вместо batch

Сейчас: `ImportAll` → `[]*Entry` → `WriteEntries`. Для 10K+ entries из KDBX
весь массив в памяти.

**Целевая модель:** streaming pipeline:
```
kdbx.Import(r) → yield Entry → Plan/WriteEntry one-by-one
```

Требует refactor WriteEntries на WriteEntry (single). Plan — тоже single.
 Dry-run — collect plans without writing, но тоже streaming.

**Оценка:** 4 часа. Низкий приоритет: 10K entries в KDBX — редкость.

### 4.2. Export: streaming вместо read-all-then-write

Сейчас: `s.List("")` → iterate → `s.Get(name)` → format row → write. Для 1K
entries с hardware token — 1K касаний. Нельзя стримить (Get — single entry).

**Частичное решение:** `--parallel` для export (как в audit). Concurrent Get
с bounded goroutine pool.

**Оценка:** 2 часа.

### 4.3. Importer registry: plugin-style loading

Сейчас: `NewRegistry()` хардкодит все importers. Добавление формата = правка
registry.go.

**Целевая модель:** `init()` self-registration:
```go
// bitwarden.go
func init() { RegisterImporter(&BitwardenImporter{}) }
```

Но это ломает testability (global state). Альтернатива: `import _ "..."` с
blank import. Или оставить как есть (9 форматов — не 60).

**Оценка:** 1 час. Низкий приоритет.

---

## 5. Bugs / edge cases для внимания

### 5.1. gokeepasslib panic на nil Content/Root

`LockProtectedEntries` и `cleanupBinaries` panic'ают. Наш guard в `kdbx.go:61-63`
unreachable. Но если библиотеку обновят и изменится behaviour — может стать reachable.

**Действие:** при следующем `gokeepasslib` upgrade — проверить что guard всё ещё
unreachable. Если станет reachable — написать тест.

### 5.2. Bitwarden Detect: operator precedence

```go
return strings.Contains(line, "folder,") || strings.Contains(line, "group,") && strings.Contains(line, "favorite,")
```

`&&` bind'ит сильнее `||`. Это значит:
- `folder,` → match (без проверки `favorite,`)
- `group,` + `favorite,` → match

**Следствие:** CSV с `folder,` но без `favorite,` (не Bitwarden) — false positive.
Пример: какой-то CSV со словом "folder" в хедере.

**Фикс:**
```go
return (strings.Contains(line, "folder,") || strings.Contains(line, "group,")) && strings.Contains(line, "favorite,")
```

**Оценка:** 5 минут.

### 5.3. csvEscape: quote char doubling edge case

`csvEscape` удваивает `"` внутри quoted string. Стандартный CSV escaping.
Но если входная строка содержит `\r\n` (Windows line ending) — оба символа
попадают в output. RFC 4180 требует что CRLF внутри quoted field — OK.
Но некоторые CSV readers ломаются.

**Действие:** проверить в fuzz test. Если ломается — нормализовать `\r\n` → `\n`
перед escape.

---

## 6. Документация

### 6.1. Man pages для import/export/audit/binary

`binpass import --help`, `binpass audit --help` — есть. Man pages — нет.
M8 milestone, не блокирует.

### 6.2. ARCHITECTURE.md §14: M2 mark as done

На ветке уже помечен как done. При merge в main — нужно обновить.

---

## Приоритеты

| # | Что | Приоритет | Время | Блокирует? |
|---|---|---|---|---|
| 1.1 | Merge ветки | P0 | 30 min | да |
| 1.2 | Mock store для CLI tests | P1 | 2 h | нет, но сильно повышает confidence |
| 5.2 | Bitwarden Detect precedence | P1 | 5 min | нет, но false positive |
| 2.2 | Export notes dedup | P2 | 1 h | нет |
| 2.4 | HIBP disk cache | P2 | 2 h | нет |
| 2.5 | Partial audit | P2 | 1 h | нет |
| 3.1 | binary coverage | P2 | 30 min | нет |
| 2.1 | UTF-16 BE | P3 | 30 min | нет |
| 2.3 | Pass re-encrypt | P3 | 4 h | нет |
| 3.2 | CLI coverage via mock store | P2 | 3 h | нет |
| 4.1 | Streaming import pipeline | P3 | 4 h | нет |
