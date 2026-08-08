# binpass — архитектура

**Что это:** `pass(1)`, переосмысленный. Тот же формат хранилища и та же поверхность команд,
но всё, ради чего в pass ставят десяток bash-расширений, встроено нативно и работает одинаково
на трёх ОС. Плюс age рядом с GPG, аппаратные ключи, tomb, и синхронизация через
git / Google Drive / Yandex.Disk / WebDAV.

* Go 1.23+, `CGO_ENABLED=0` (с одним исключением, §6.3), статика под linux/darwin/windows × amd64/arm64.
* Один бинарь `binpass` + опционально `binpass-agent`.
* Сервера нет. Синхронизация — клиент ↔ транспорт, без посредников.

---

## 0. Позиционирование

Прошлая итерация пыталась мимикрировать под bash-внутренности pass, чтобы `pass-otp` и
`pass-update` заводились немодифицированными. Это была ошибка: слой совместимости получался
самой хрупкой частью системы и при этом воспроизводил функциональность, которую проще написать
нативно за меньшее время.

Новая позиция:

| Что | Решение |
|---|---|
| Формат хранилища | **Идентичен pass.** Дерево файлов, `.gpg-id`, `.age-recipients`. Не трогаем |
| Поверхность CLI и stdout | **Байт-в-байт как pass.** Чтобы passmenu / rofi-pass / browserpass / pass-git-helper / QtPass работали без правок |
| Функциональность плагинов pass | **Нативно в Go**, кроссплатформенно, с тестами (§5) |
| Расширяемость | **Своя система плагинов** (§4) — проще, чем у pass, и не только на bash |
| Системный keystore | **Заменяем на Linux** (`org.freedesktop.secrets`), **интегрируемся** на macOS/Windows (§6) |
| bash-расширения pass, сорсящие внутренности | **Не поддерживаем.** Явно и в документации |

Последняя строка — единственная потеря, и она осознанная. Всё, что эти расширения делают,
есть в §5 нативно.

---

## 1. Хранилище

```
$PASSWORD_STORE_DIR  (=$BINPASS_DIR, default ~/.password-store)
├── .gpg-id                     # GPG-получатели (pass)
├── .gpg-id.sig                 # подпись, если задан SIGNING_KEY
├── .age-recipients             # age-получатели (passage)
├── .binpass/
│   └── plugins/                # плагины стора (синхронизируются вместе с ним)
├── .gitattributes
├── github.com/
│   ├── alice.gpg
│   └── bob.age                 # age и gpg в одном дереве, крипто по расширению
└── bank/
    ├── .gpg-id                 # переопределение получателей для поддерева
    └── tinkoff.gpg

$XDG_DATA_HOME/binpass/          # САЙДКАР, вне стора — pass его не видит
├── sync/{state.db, base/, journal.wal}
├── remotes.age                 # OAuth-токены Drive/Yandex, пароли WebDAV
├── identities.age
└── plugins/                    # локально установленные плагины
```

Состояние синхронизации принципиально живёт **вне хранилища**: оно device-specific, и попав
в стор, уехало бы в git-историю и на Google Drive, а `pass git status` показывал бы мусор.

### Формат секрета

Ровно как в pass, ничего своего: первая строка — пароль, дальше свободный текст.

```
hunter2
otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub
url: https://github.com
username: alice
```

`key: value` парсим для `--field`, но не требуем. OTP — `otpauth://` в любой строке, как у `pass-otp`.
Бинарники — `name.b64.gpg` с base64 внутри (gopass-совместимо).

---

## 2. Крипто: GPG и age равноправно

```go
// Crypto — шифрование одной записи. Реализация выбирается по расширению файла.
type Crypto interface {
    Ext() string                                              // ".gpg" | ".age"
    Encrypt(w io.Writer, plaintext []byte, rcp []Recipient) error
    Decrypt(r io.Reader) ([]byte, error)
    ParseRecipients(dir string) ([]Recipient, error)          // .gpg-id | .age-recipients
}
```

**GPG** — через внешний бинарь `gpg`, не через Go-реализацию OpenPGP. Так работают smartcard,
gpg-agent, pinentry, кейринги и `PASSWORD_STORE_SIGNING_KEY`, а результат совпадает с pass
бит-в-бит. `ProtonMail/go-crypto` — фолбэк для окружений без gpg, с честным предупреждением,
что аппаратные ключи там не заведутся.

**age** — `filippo.io/age`. Дефолт для новых хранилищ: формат проще, ключи короче, аппаратная
поддержка через плагины (§3).

Оба сосуществуют в одном дереве. `binpass migrate --to=age` переводит стор, `--dry-run` показывает план.

---

## 3. Аппаратные ключи

Отдельный раздел, потому что это одно из главных «зачем» проекта.

### 3.1 Абстракция identity

```go
// Identity — источник ключа расшифровки. Не обязательно файл.
type Identity interface {
    Kind() Kind                  // file | passphrase | pgpcard | agePlugin | tpm | fido2
    Unwrap(ctx context.Context, stanzas []*age.Stanza) ([]byte, error)
    RequiresPresence() bool      // нужно физическое касание
    Describe() string            // "YubiKey 5C серия 12345678, slot 9a"
}
```

Порядок поиска: `--identity` → `BINPASS_IDENTITY` → `identities.age` → `~/.config/age/keys.txt` →
`$PASSAGE_IDENTITIES_FILE` → подключённые аппаратные токены (автодетект). Если подходят несколько —
пробуем по очереди, спрашиваем только при неоднозначности.

### 3.2 Поддерживаемое железо

| Устройство | Механизм | Как |
|---|---|---|
| YubiKey / Nitrokey (OpenPGP) | GPG smartcard | Через gpg-agent, работает из коробки для `.gpg` |
| YubiKey (PIV) | `age-plugin-yubikey` | Ключ не покидает токен, PIN + опц. касание |
| Любой FIDO2 (YubiKey, SoloKey, Token2) | `age-plugin-fido2-hmac` | `hmac-secret`, касание обязательно |
| Apple Secure Enclave | `age-plugin-se` | Touch ID / Apple Watch как подтверждение |
| TPM 2.0 | `age-plugin-tpm` | Привязка к машине, без внешнего токена |

Плагины age вызываются по **штатному age-plugin протоколу** (stdio, бинарь `age-plugin-*` на PATH) —
свою реализацию криптографии токенов не пишем: там легко ошибиться, а протокол уже стандартизован.

### 3.3 Что именно защищается ключом

Три независимых уровня, включаются по отдельности:

1. **Записи.** Recipient — аппаратный. Каждая расшифровка требует касания. Максимальная защита,
   но `binpass grep` по всему стору превращается в пытку. Разумно для поддерева `bank/`.
2. **Identity-файл.** `identities.age` завёрнут в аппаратный recipient, разворачивается один раз
   за сессию агента. Компромисс по умолчанию.
3. **Tomb/coffin.** Ключ от контейнера (§7) на токене — вынул ключ, стор физически недоступен.

Конфигурация — на уровне подкаталогов через `.age-recipients`, то есть тем же механизмом,
что и обычный шаринг.

### 3.4 Второй фактор на само хранилище

Отдельная опция `unlock.require_presence`: даже когда identity уже в агенте, операция
`show`/`edit` требует касания токена. Реализуется пустой FIDO2-assertion — дёшево и не ломает
кеширование ключа.

### 3.5 YubiKey OATH для OTP

Бонус: TOTP-секреты можно держать не в сторе, а в OATH-апплете YubiKey.
`binpass otp --oath <name>` читает код прямо с токена (`ykman oath accounts code`).
Секрет тогда вообще не существует на диске. `binpass otp move-to-oath <name>` переносит.

---

## 4. Система плагинов

Задача: расширяемость не хуже pass, но без сорсинга bash-функций.

### 4.1 Три уровня

**Уровень 1 — subcommand на PATH (git-style).** Самый простой, любой язык.
Файл `binpass-foo` на PATH или в `$XDG_DATA_HOME/binpass/plugins/` → появляется команда `binpass foo`.

Плагин получает окружение и **стабильный CLI обратно в binpass** — это замена сорсингу функций:

```bash
#!/usr/bin/env bash
# binpass-lastused — показать давно не использованные записи
: "${BINPASS_STORE:?}" "${BINPASS_BIN:?}"

"$BINPASS_BIN" ls --format=json | jq -r '.[] | select(.used_days_ago > 365) | .path'
```

Экспортируемое окружение: `BINPASS_BIN`, `BINPASS_STORE`, `BINPASS_VERSION`, `BINPASS_PLUGIN_DIR`,
`BINPASS_API=1`, `PASSWORD_STORE_DIR` (для скриптов, ожидающих pass).

Машиночитаемый вывод у всех команд — `--format=json|yaml|template` — чтобы плагины не парсили
человекочитаемый stdout. Схема вывода версионируется, ломающие изменения — только со сменой
`BINPASS_API`.

**Уровень 2 — декларативные рецепты.** Для типовых вещей код не нужен:

```yaml
# ~/.config/binpass/recipes/rotate-github.yaml
name: rotate-github
description: Сменить пароль GitHub и записать новый
match: "github.com/*"
steps:
  - generate: { length: 32, symbols: true }
  - open_url: "https://github.com/settings/admin"
  - confirm: "Пароль изменён на сайте?"
  - commit: "Rotate GitHub password"
```

**Уровень 3 — типизированные плагины через `hashicorp/go-plugin`** (gRPC поверх stdio).
Для глубокой интеграции: свой транспорт синхронизации, свой источник identity, свой тип секрета,
свой импортёр.

```go
// Плагин реализует один или несколько интерфейсов ядра.
type RemotePlugin  interface { Remote }            // новый бэкенд синхронизации
type IdentityPlugin interface { Identity }         // новый источник ключа
type SecretPlugin  interface {                     // новый тип секрета: рендер, валидация, поля
    Kind() string
    Parse([]byte) (Secret, error)
    Render(Secret, RenderOpts) ([]byte, error)
}
```

Транспорт — gRPC, значит плагины можно писать на любом языке, и падение плагина не роняет binpass.

### 4.2 Модель разрешений

Плагины видят пароли. Значит без capability-модели это дыра, а не фича.

```yaml
# plugin.yaml — манифест, обязателен
name: pass-import-bitwarden
version: 1.2.0
api: 1
capabilities:
  read_paths: ["**"]           # что может читать
  write_paths: ["import/**"]   # что может писать
  decrypt: false               # нужен ли ДОСТУП К PLAINTEXT
  network: ["vault.bitwarden.com"]  # белый список хостов
  exec: []                     # какие внешние бинари может звать
```

* При установке — показ манифеста и явное подтверждение. `decrypt: true` подсвечивается отдельно.
* Гранты пишутся в `plugins.lock` с хешем бинаря плагина; изменился хеш — переспрашиваем.
* Сеть режется на уровне процесса (плагин ходит наружу только через прокси ядра, если объявил хосты).
* Плагины уровня 3 запускаются с отдельным umask, без наследования агентского сокета.
* `binpass plugin audit` показывает, у кого какие права.

Полноценной песочницы не обещаем: на уровне 1 плагин — это обычный процесс пользователя,
и он может обойти ограничения. Модель защищает от небрежного плагина, не от вредоносного.
Для настоящей изоляции есть опциональный WASM-рантайм (`wazero`) на уровне 3, но там нет
доступа к сети и файлам вовсе — годится для трансформаций и валидаторов.

### 4.3 Дистрибуция

```
binpass plugin search <query>
binpass plugin install <name|url|path>     # с проверкой подписи (minisign)
binpass plugin list | info | update | remove
binpass plugin audit
```

Реестр — git-репозиторий с индексом; ничего централизованного, установка по URL всегда работает.
Плагины в `.binpass/plugins/` внутри стора синхронизируются вместе с ним (удобно, но требует
доверия ко всем, у кого есть доступ — предупреждаем).

---

## 5. Нативные аналоги плагинов pass

Всё это встроено, кроссплатформенно и покрыто тестами.

| Плагин pass | Команда binpass | Что сверх оригинала |
|---|---|---|
| `pass-otp` | `binpass otp` | HOTP-счётчик синхронизируется корректно (§8.5), `--watch`, YubiKey OATH, QR |
| `pass-update` | `binpass update` | Массовая ротация по маске, интеграция с рецептами (§4.1), политика длины из конфига |
| `pass-audit` | `binpass audit` | HIBP по k-anonymity (5-символьный SHA-1 префикс, полный хеш не покидает машину, кеш ответов в памяти, `--no-hibp` для offline), слабые через zxcvbn (score < 2), переиспользованные через SHA-1 хеш-группы, просроченные через `expire:`/`expires:`/`expiry:` поля (RFC 3339, ISO, европейский формат, относительные "Nd"), severity buckets mutually exclusive (Critical + Warning + Info + Clean = Audited), `--format=json`, `--parallel`, пароли никогда не выводятся |
| `pass-import` | `binpass import` | 9 форматов: KeePass KDBX (gokeepasslib, вложенные группы, TOTP, custom fields, attachments → `name.b64`), Bitwarden CSV, 1Password CSV, LastPass CSV (http://sn placeholder, CP1251 decode), Chrome CSV, Firefox CSV (URL→domain fallback), Enpass CSV (Recycle Bin filter), pass/gopass (ciphertext copy для re-encrypt). Автоопределение по содержимому (`Registry.Detect`), `--dry-run` (`Plan`/`FormatPlan`), `--force` для overwrite, `--format` для explicit selection, `--encoding` для non-UTF-8, BOM strip (UTF-8/UTF-16 LE/BE), multiline CSV fields, path normalisation + traversal reject (`ValidatePath`), dedup (`DeduplicatePaths`), KDBX password с TTY (`readSecret`, no echo). Плюс `binpass export` (CSV, WARNING о plaintext) |
| `pass-tomb` / `pass-coffin` | `binpass tomb` | Кроссплатформенно (§7) |
| `pass-file` | `binpass binary` | Стрим без буферизации в память, `sum`, детект бинарности |
| `pass-genphrase` | `binpass generate --words=5` | Diceware, EFF-словари, несколько языков |
| `pass-rotate` | `binpass rotate` | Рецепты + известные URL смены пароля (`.well-known/change-password`) |
| `pass-checkup` | `binpass doctor` | Проверка стора, ключей, прав, recipients, зависших lock'ов |
| `pass-clip` | встроено в `-c` | Автоочистка + восстановление прежнего содержимого буфера |
| `pass-grid` / TUI | `binpass tui` | bubbletea: поиск, дерево, просмотр, OTP с обратным отсчётом |
| `passmenu` / `rofi-pass` | работают как есть | Держим stdout-совместимость; плюс `binpass menu` со встроенным dmenu/fzf-режимом |
| `browserpass` | работает как есть | Зовёт gpg напрямую → Tier совместимости по `.gpg`; для `.age` нужен `binpass gpg-shim` в его конфиге |
| `pass-git-helper` | `binpass git-credential` | Нативный git credential helper, конфиг маппинга URL→запись |
| `pass-secret-service` | `binpass ss` | Атрибуты зашифрованы (слепой индекс), ACL до выдачи секрета, а не уведомление после (§6) |

Плюс то, чего в pass-экосистеме нет:

* `binpass history <name>` — все версии записи из git с diff по полям.
* `binpass expire` — TTL на записи, напоминание о ротации.
* `binpass qr <name>` — QR для переноса на телефон.
* `binpass fill` — вывод в формате для автозаполнения (`--format=json`).
* `binpass watch` — реакция на изменения стора (для интеграций).

### 5.1 import/export: модель данных и ограничения

Импорт — двухфазный процесс: **Detect → Import → Plan → WriteEntries**. Разделение
планирования и записи делает `--dry-run` естественным: Plan не мутирует стор.

**Importer interface:**

```
Name() string                     — для --format и вывода
Detect(io.Reader) bool            — автоопределение по содержимому (не по расширению)
Import(io.Reader) iter.Seq2[Entry, error]  — потоковая конвертация
```

**Entry** — промежуточное представление. Содержит Title, Group, Path, Password,
Username, URL, Notes, TOTPURI, Fields, Attachments. Экспорт маппит Entry на store path
(через NormalizePath + ValidatePath) и pass-format secret (через ToSecret).

**Registry** — список всех импортёров, с Detect/DetectReader (прочитает peek-буфер и
вернёт Reader обратно) и ByName (для --format).

**Критичные инварианты:**

1. `ValidatePath` reject'ит `../`, пустые сегменты, leading `/`. Нормализация
   через `NormalizePath` делает best-effort санитизацию, но финальный check —
   перед записью.
2. KDBX password — только с TTY (`readSecret`, no echo), никогда из argv (§3).
3. TOTP-секреты приводятся к `otpauth://`: raw base32 → `otpauth://totp/...`,
   уже готовый URI — passthrough.
4. Attachments → отдельные записи `name.b64` с base64-encoded content (gopass convention, §1).
5. CSV reader обрабатывает BOM (UTF-8, UTF-16 LE/BE), non-UTF-8 encoding
   (auto-detect CP1251/ISO-8859-1 или `--encoding`), multiline fields.
6. `DeduplicatePaths` — индекс-based, первый occurrence сохраняет имя, последующие
   получают `-2`, `-3` suffix. Mutually exclusive с store-level conflict detection.
7. `Plan` проверяет conflicts (entry exists in store) **до** записи. `WriteEntries`
   с `force=false` — skip при conflict, с `force=true` — overwrite.
8. Export — plaintext CSV. WARNING в Long description команды.

**Ограничения текущей реализации:**

* 9 форматов (не 60+). Расширение — добавление Importer implementations.
* Pass/gopass importer копирует ciphertext как attachment для re-encrypt, не
  расшифровывает. Для корректного re-encrypt нужен source store's crypto backend.
* Export выводит `sec.Body()` (включая structured fields) в notes-колонку CSV.
  Для чистого экспорта — только Notes-часть body.

### 5.2 audit: модель проверок и вывод

Audit — **decrypt-all-then-check**. Расшифровка всего стора — обязательный шаг;
при аппаратном ключе это N касаний токена. `--parallel` включает concurrent decryption,
но не является default при обнаружении hardware token.

**Четыре проверки:**

| Проверка | Severity | Механизм |
|---|---|---|
| Leaked (HIBP) | Critical | k-anonymity: SHA-1 → 5-char prefix → API → suffix comparison. Full hash не покидает машину. Cache in memory. `--no-hibp` = noopHIBP |
| Weak | Warning | zxcvbn score < 2 |
| Reused | Warning | SHA-1 hash grouping across entries |
| Expired | Info | `expire:`/`expires:`/`expiry:` fields, RFC 3339 / ISO / European / relative "Nd" |

**Severity buckets mutually exclusive:** entry contributes to worst severity only.
Critical + Warning + Info + Clean = Audited. Это гарантирует, что entry с
Critical + Warning не засчитывается дважды.

**HIBP error handling:** при ошибке HIBP (network, 5xx) — downgrade to Warning
("HIBP check failed"), не Critical (не можем подтвердить leak).

**Вывод:**

* `--format=text` (default): grouped by severity, entry names + findings.
  Passwords never appear.
* `--format=json`: structured `Report` (entries, skipped, stats). Passwords never appear.
* Exit code non-zero при Critical findings (CI gate).

**HIBPClient:**

```
NewHIBPClient()          — production: api.pwnedpasswords.com/range/
noopHIBP                  — offline (--no-hibp)
HIBPClient.Check(ctx, pw) — cache by prefix, mutex-protected
```

Кеш — in-memory, key = 5-char prefix. Один API call на уникальный prefix,
повторные passwords с тем же prefix — cache hit.

### 5.3 binary: бинарные секреты

Заменяет `pass-file`. Бинарные записи — обычные зашифрованные записи с именем,
заканчивающимся на `.b64`, содержимое которых — base64-кодированные исходные данные.
Совместимо с gopass.

**Команды:**

| Команда | Действие |
|---|---|
| `binpass binary cat <name>` | Декодировать и вывести в stdout |
| `binpass binary sum <name>` | SHA-256 декодированных данных |
| `binpass binary copy <name> <file>` | Закодировать файл в base64 и сохранить (оригинал остаётся) |
| `binpass binary move <name> <file>` | То же, но удалить оригинал |

**Потоковость:** Cat и Sum декодируют base64 через `io.Copy` — полный decoded
контент не буферизуется. Store кодирует за один проход, но результирующая
base64-строка должна поместиться в память (ограничение crypto-слоя).

**Критичные инварианты:**

1. Запись без суффикса `.b64` — `ErrNotBinary`.
2. `Store` с `force=false` спрашивает подтверждение при перезаписи (CLI level).
3. `DetectBinary` — эвристика для отображения (single-line base64), не для
   security decisions.
4. Аттачменты из KDBX-импорта (§5.1) используют тот же формат `name.b64`.

---

## 6. binpass как системный keystore

Цель: приложения, которые уже умеют работать с системным хранилищем паролей, должны прозрачно
попадать в binpass, ничего не зная о нём. Chrome, VS Code, Docker, NetworkManager, GNOME Online
Accounts, `git`, `kubectl`, Nextcloud, Evolution, Element — все они ходят в keystore
и должны получать секреты из твоего стора.

### 6.1 Linux: провайдер `org.freedesktop.secrets`

Полная реализация Secret Service API (аналог `pass-secret-service`, gnome-keyring, KWallet)
прямо в `binpass-agent`. Демон занимает имя на session bus, реализует объекты
`Service`, `Collection`, `Item`, `Session`, `Prompt`; поставляется с systemd user unit
и D-Bus activation-файлом.

**Маппинг на стор:**

```
/org/freedesktop/secrets/collection/login   →  $STORE/secret-service/login/
/org/freedesktop/secrets/aliases/default    →  алиас на неё же
  └── item/1a2b3c…                          →  $STORE/secret-service/login/1a2b3c.age
```

Файл — обычный pass-секрет, читаемый `binpass show` и `pass show`:

```
correct-horse-battery-staple
label: GitHub token
attr.application: git
attr.server: github.com
attr.username: alice
created: 1754651234
```

**Шифрование транспорта.** Обязательны оба алгоритма из спецификации: `plain` и
`dh-ietf1024-sha256-aes128-cbc-pkcs7` (DH на группе MODP-1024, ключ через SHA-256 HKDF,
AES-128-CBC с PKCS#7). Без второго libsecret работать не будет.

### 6.2 Проблема атрибутов и слепой индекс

`pass-secret-service` хранит атрибуты в открытом виде — это заявлено в его README прямым текстом.
Но атрибуты — это `server`, `username`, `application`, `url`. То есть полная карта всех твоих
аккаунтов лежит в git-репозитории и на Google Drive нешифрованной, даже когда сами пароли зашифрованы.

Решение опирается на важное свойство спецификации: **`SearchItems` делает точное совпадение**
по парам ключ-значение, а не поиск по подстроке. Значит детерминированный HMAC работает
как полноценный поисковый индекс:

```go
// blind вычисляет слепой ключ атрибута для точного поиска без расшифровки.
// indexKey выводится из identity, наружу не попадает.
func blind(indexKey []byte, name, value string) string {
    m := hmac.New(sha256.New, indexKey)
    m.Write([]byte(name)); m.Write([]byte{0}); m.Write([]byte(value))
    return base32.StdEncoding.EncodeToString(m.Sum(nil)[:16])
}
```

* Атрибуты в открытом виде лежат **внутри зашифрованного файла**.
* Рядом — `secret-service/.index.age`: карта `blind(attr) → [itemID]`.
* Поиск при разблокированном сторе: считаем HMAC от запроса, идём в индекс. Расшифровывать
  ничего не нужно, скорость — как у plaintext-индекса.
* Провайдер (git-хостинг, Drive) видит только base32-хеши. Утекает лишь то, что два элемента
  разделяют одинаковое значение атрибута — на порядки меньше, чем полный список серверов и логинов.
* При заблокированном сторе `SearchItems` возвращает элементы помеченными `Locked` и объект
  `Prompt` — ровно как предписывает спецификация.

Индексный ключ живёт в агенте и разворачивается вместе с identity. Пересборка индекса —
`binpass ss reindex`, вызывается автоматически после `sync`.

### 6.3 Контроль доступа

Слабое место всей модели Secret Service: **session bus не изолирует приложения**. Любой процесс
пользователя может запросить любой секрет. gnome-keyring это никак не ограничивает,
`pass-secret-service` — только уведомляет постфактум через `--notify-on-access` и умеет
показать последнего обратившегося.

binpass добавляет политику **до** выдачи секрета:

```yaml
# ~/.config/binpass/secret-service.yaml
default: prompt              # allow | deny | prompt
remember: 8h                 # сколько помнить решение пользователя
rules:
  - app: /usr/bin/git
    attrs: { server: "github.com" }
    action: allow
  - app: /usr/lib/firefox/firefox
    collection: login
    action: prompt
  - app: "*"
    attrs: { application: "ssh" }
    action: deny
notify: on-access            # off | on-access | on-prompt
audit: true                  # журнал: кто, что, когда
```

Идентификация вызывающего: unique name на шине → `GetConnectionCredentials` →
PID → `/proc/PID/exe`, на systemd — через pidfd, что закрывает гонку с переиспользованием PID.
**Честная оговорка:** и pidfd не спасает от процесса, который подменил себя после старта;
это ограничение самой модели D-Bus, а не реализации. Политика защищает от случайного
и неаккуратного доступа, не от целенаправленной атаки локального злоумышленника.

Дополнительно:

* `binpass ss last-accessor <id>` — кто последним читал секрет (PID, UID, имя программы, время).
* `binpass ss audit` — полный журнал доступов.
* Форсированный `Lock` при блокировке экрана, suspend и по таймеру; `--forget-on-lock`
  заставляет gpg-agent/binpass-agent забыть ключ.
* `require_presence` (§3.4) действует и здесь: касание токена на выдачу секрета приложению.

### 6.4 Сосуществование с gnome-keyring и KWallet

Имя `org.freedesktop.secrets` на шине может занять только один демон. Поэтому:

* `binpass ss doctor` определяет, кто сейчас владеет именем, и печатает точные команды
  для отключения конкурента (`systemctl --user mask gnome-keyring-daemon.socket` и т.п.).
* Режим `--takeover=refuse|wait|replace` — что делать, если имя занято.
* **Импорт**: `binpass import keyring` вытягивает существующие элементы из gnome-keyring
  или KWallet через тот же Secret Service API и складывает в стор — переезд без потерь.
* Приложения в Flatpak и Snap ходят не напрямую, а через `org.freedesktop.portal.Secret`.
  Портал проксирует в тот же демон, так что достаточно, чтобы `xdg-desktop-portal` был настроен;
  `ss doctor` это проверяет.

### 6.5 macOS и Windows

Здесь системный keystore заменить нельзя — только интегрироваться. Что и делаем, в обе стороны.

**macOS Keychain:**

* `binpass keychain import|export|sync` — двусторонний перенос элементов.
* age-identity можно завернуть в Keychain-элемент, защищённый Touch ID / Apple Watch
  (`kSecAccessControlUserPresence`) — разблокировка стора отпечатком без внешнего токена.
* `binpass ss` на macOS не поднимает D-Bus; вместо него работают интеграции §6.6.

**Windows Credential Manager:**

* `binpass wincred import|export|sync` через `CredRead`/`CredWrite`.
* Обёртка identity через DPAPI/CNG с привязкой к пользователю, опционально к TPM.
* Windows Hello (платформенный WebAuthn-аутентификатор) как фактор разблокировки —
  тот же механизм, что FIDO2 в §3.2.

### 6.6 Интеграции уровня приложений

Работают на всех трёх ОС, D-Bus не требуют — часто это практичнее, чем полноценный keystore:

| Интеграция | Команда | Что даёт |
|---|---|---|
| git | `binpass git-credential` | Пароли и токены для push/pull, маппинг URL → запись |
| Docker / containerd | `docker-credential-binpass` | Логины в registry по протоколу credential helper (JSON через stdin/stdout) |
| SSH | `SSH_ASKPASS=binpass askpass` | Пароли к ключам и хостам |
| sudo | `SUDO_ASKPASS=binpass askpass` | То же для sudo |
| kubectl | `binpass k8s-credential` | Плагин `client.authentication.k8s.io/v1` |
| AWS CLI | `credential_process = binpass aws` | Ключи не лежат в `~/.aws/credentials` |
| Ansible | `binpass ansible-vault-pass` | Пароль от vault из стора |
| netrc | `binpass netrc --generate` | Временный `.netrc` в tmpfs для legacy-утилит |
| Переменные окружения | `binpass exec -- <cmd>` | Инъекция секретов в окружение дочернего процесса, без записи на диск |

`binpass exec` — самый полезный из списка: `binpass exec --env=DB_PASS=prod/db -- ./app`
подставляет секрет в переменную окружения ровно на время жизни процесса.

---

## 7. Tomb и coffin

Цель: стор не просто зашифрован по файлам, а целиком скрыт, когда не используется —
не видны ни имена, ни структура, ни факт существования записей.

### 7.1 Две стратегии

**Coffin (кроссплатформенно, дефолт).** Весь стор — один зашифрованный архив
`store.coffin.age`. Открытие: расшифровка в приватный tmpfs-каталог (Linux) или в
каталог с 0700 и явным затиранием (macOS/Windows). Закрытие: перешифровка + `shred`.

* Работает везде, включая Windows, без прав root.
* Ограничение: слабое место — plaintext-каталог во время сессии. Митигируем tmpfs, `mlock`
  для мелких файлов, автозакрытием по таймауту и на события ОС (suspend, screen lock, logout).
* Ключ от coffin — обычный age-recipient, значит **сразу поддерживает аппаратные ключи**.

**Tomb (Linux, максимальная защита).** LUKS-контейнер через `cryptsetup`, совместимый
с `pass-tomb`/`tomb(1)`.

* Данные в plaintext существуют только в маппинге dm-crypt, на диск не попадают.
* Ключ-файл контейнера сам зашифрован age/GPG → аппаратный токен как ключ от tomb.
* Нужен root (или соответствующая polkit-политика) — честно предупреждаем.
* Совместимость: существующий tomb от `pass-tomb` открывается binpass'ом.

**macOS** — третий вариант: encrypted APFS sparse bundle через `hdiutil`, ключ в Keychain
или на аппаратном токене. По защите ближе к tomb, по удобству — к coffin.

### 7.2 Команды

```
binpass tomb init [--type=coffin|luks|sparsebundle] [--size=1G] [--recipient=age1...]
binpass tomb open  [--timer=1h]     # автозакрытие
binpass tomb close [--force]
binpass tomb status
```

Автозакрытие вешается на: таймер, блокировку экрана (D-Bus / IOKit / WinAPI), suspend, logout,
и `binpass-agent` forget. При аварийном завершении — `binpass doctor` находит незакрытый контейнер.

### 7.3 CGO

`CGO_ENABLED=0` держим для основного бинаря. LUKS-путь зовёт внешний `cryptsetup`, а не линкуется
с libcryptsetup — иначе теряется статика и кроссплатформенная сборка. Единственное возможное
исключение — FIDO2 через `go-libfido2`, поэтому по умолчанию идём через `age-plugin-fido2-hmac`
(внешний бинарь), а нативную сборку выносим под build-tag `cgo_fido2`.

---

## 8. Синхронизация

### 8.1 Модель

Хранилище — обычные файлы, значит синхронизация файловая. Состояние в `sync/state.db` (bbolt):

```go
// FileState — что binpass знает о файле на момент последней успешной синхронизации.
type FileState struct {
    Path      string        // "github.com/alice.gpg"
    Hash      [32]byte      // blake3 от ШИФРОТЕКСТА — ключ для сравнения не нужен
    Size      int64
    ModTime   time.Time
    Version   VersionVector // {deviceID: counter}
    RemoteRev string        // git sha | ETag | Drive revision
}
```

Хеш от шифротекста: `binpass sync` работает при заблокированном сторе. Обратная сторона —
GPG недетерминирован, перешифровка того же plaintext даёт другой шифротекст. Поэтому первичный
детектор изменений — `(size, mtime)`, хеш подтверждает.

### 8.2 Интерфейс транспорта

```go
// Remote — транспорт синхронизации. Одинаков для git, Drive, Yandex, WebDAV, S3.
type Remote interface {
    Name() string
    Caps() Caps   // Atomic, History, Locking, Rename, Watch

    List(ctx context.Context) ([]RemoteFile, error)
    Get(ctx context.Context, path string) (io.ReadCloser, string, error)
    Put(ctx context.Context, path string, r io.Reader, expectRev string) (string, error)
    Delete(ctx context.Context, path string, expectRev string) error
    Rename(ctx context.Context, from, to string) error
    Lock(ctx context.Context) (Unlock, error)
    Close() error
}
```

Плагины уровня 3 могут реализовать этот интерфейс и добавить свой бэкенд.

### 8.3 git

* Системный `git` (credential helpers, ssh-agent, подпись коммитов, прокси), `go-git` — фолбэк.
* Автокоммит с теми же сообщениями, что у pass (`Add given password for X to store.`) —
  история неотличима.
* `.gitattributes`: `*.gpg binary`, `*.age binary`, merge-driver `binpass merge-driver` → §8.5.
* Работает с любым существующим pass-репозиторием без конвертации.

### 8.4 Google Drive, Yandex.Disk, WebDAV, S3

Первоклассная поддержка, а не «настройте rclone сами».

**Встроенный OAuth.** `binpass remote add gdrive` поднимает локальный редирект на `127.0.0.1`,
открывает браузер, забирает токен, кладёт в `remotes.age`. Никаких предварительных конфигов.
Yandex.Disk — аналогично через Яндекс OAuth. Для headless — device-flow с кодом.

**Под капотом rclone как библиотека**, точечные импорты (не `backend/all`, иначе бинарь пухнет
на десятки мегабайт; полный набор — под build-tag `rclone_full`):

```go
import (
    _ "github.com/rclone/rclone/backend/drive"
    _ "github.com/rclone/rclone/backend/yandex"
    _ "github.com/rclone/rclone/backend/webdav"
    _ "github.com/rclone/rclone/backend/s3"
)
```

Существующий `~/.config/rclone/rclone.conf` подхватывается, если есть — тогда доступны все
40+ бэкендов rclone разом.

Особенности, которые реально стреляют:

* **Атомарности нет нигде.** S3 — `If-Match` по ETag; Drive/WebDAV/Yandex — advisory-lock
  `.binpass.lock` с TTL и владельцем + verify-after-write. `Caps()` возвращает `WeakAtomic`,
  движок добавляет проверку после записи.
* **Rate limits.** Drive: 1000 запросов/100 с на пользователя; Yandex жёстче. Backoff с jitter,
  батчинг, уважение `Retry-After`. Стор на 2000 записей нельзя лить по файлу за запрос —
  дельта-синхронизация обязательна.
* **Yandex.Disk** доступен и как WebDAV (`https://webdav.yandex.ru`), и нативно.
  Нативный быстрее и не упирается в лимиты WebDAV-шлюза — он и по умолчанию.
* **Drive и регистр имён.** Drive допускает два файла с одинаковым именем в папке.
  При обнаружении дубля — не угадываем, а зовём конфликт-резолвер.
* **Что видит провайдер:** только шифротексты и файлы получателей. Но **имена записей видны** —
  это врождённое свойство pass. Опция `--obfuscate` (base32 HMAC от пути, карта имён
  в зашифрованном индексе) есть, но ломает совместимость с pass; либо tomb/coffin (§7),
  который решает вопрос радикально — наружу уезжает один блоб.

### 8.5 Конфликты

| Ситуация | Действие |
|---|---|
| VV равны | ничего |
| Локальный доминирует | push |
| Удалённый доминирует | pull |
| **Расходятся** | конфликт |
| Расходятся, шифротексты идентичны | слить VV, файл не трогать |
| Расходятся, в секрете HOTP | автомерж по `max(counter)` |
| delete vs edit | побеждает edit, warning |

Дефолт — обе копии на диск, ничего не теряется молча:

```
github.com/alice.gpg                                    ← удалённая
github.com/alice.conflict-thinkpad-20260808T142233.gpg  ← локальная
```

`binpass conflicts list|diff|resolve` — пофайловый diff расшифрованных секретов, пароль
замаскирован (`--show-secrets` снимает). Автомержа полей по умолчанию нет: слишком легко
получить секрет-франкенштейн с логином от одной версии и паролем от другой.

HOTP — единственное место, где движок синхронизации заглядывает внутрь секрета, и это неизбежно:
счётчик расходится на двух устройствах закономерно, а не случайно.

### 8.6 Надёжность

* Всё работает оффлайн, `sync` догоняет.
* Запись: `tmp в том же каталоге → fsync → rename → fsync(dir)`, права 0600/0700.
* WAL реиграется при старте, если процесс убили посреди операции.
* `binpass fsck` сверяет дерево, state.db и recipients, чинит расхождения.

---

## 9. CLI

Первая группа — команды pass, ведут себя идентично, включая коды возврата и формат вывода дерева.

```
binpass init [--path=subdir] [--age|--gpg] <recipient>...
binpass [ls] [subfolder]            binpass find <term>...
binpass show [-c[n]] [--field=f] [--qr] <name>
binpass insert [-m] [-f] <name>     binpass edit <name>
binpass generate [-n] [-c] [-f] [-i] [--words=N] <name> [len]
binpass rm [-r] [-f] <name>         binpass mv|cp [-f] <old> <new>
binpass grep [opts] <pattern>       binpass git <args>...
binpass version | help

--- нативные аналоги плагинов ---
binpass otp | update | audit | import | export | rotate | binary | doctor | menu

--- сверх того ---
binpass ss run|status|doctor|reindex|audit|last-accessor   # Secret Service (Linux)
binpass keychain import|export|sync   # macOS
binpass wincred import|export|sync    # Windows
binpass exec --env=VAR=path -- <cmd>  # инъекция секретов в окружение
binpass askpass | git-credential | k8s-credential | aws | netrc
binpass tomb init|open|close|status
binpass sync [--remote=NAME|all] [--dry-run]
binpass remote add gdrive|yandex|webdav|s3|git <name> [url]
binpass conflicts list|diff|resolve
binpass recipients add|remove|list  binpass reencrypt [--to=age] [path]
binpass identity list|add|test      # аппаратные ключи, диагностика
binpass plugin search|install|list|info|update|remove|audit
binpass history|expire|qr|fill|watch|tui
binpass git-credential                # helper для git
binpass completion bash|zsh|fish|powershell
```

Всё `PASSWORD_STORE_*` уважается как есть, `BINPASS_*` приоритетнее:
`DIR`, `CLIP_TIME`, `UMASK`, `GENERATED_LENGTH`, `CHARACTER_SET[_NO_SYMBOLS]`, `SIGNING_KEY`, `GPG_OPTS`, `KEY`.

Клипборд: X11 `xclip`, Wayland `wl-copy`, macOS `pbcopy`, Windows WinAPI — с автоочисткой
и восстановлением прежнего содержимого. `edit` — файл в tmpfs (Linux) или 0600 + явное затирание.
Пароли читаются только с TTY/stdin, никогда из argv.

`binpass version` — версия, коммит, дата сборки, Go, ОС/арх (ldflags).

---

## 10. Модель угроз

| Угроза | Митигация |
|---|---|
| Компрометация Drive / Yandex / WebDAV | Провайдер видит только шифротекст, ключей нет |
| Провайдер видит имена записей | Врождённое для pass. `--obfuscate` или tomb/coffin (§7) |
| Провайдер видит атрибуты keystore (server, username, url) | Атрибуты внутри шифротекста, поиск по слепому HMAC-индексу (§6.2). Утекает только равенство значений |
| Чужое приложение читает секрет через D-Bus | Политика allow/deny/prompt **до** выдачи, журнал, `last-accessor` (§6.3). Ограничение модели D-Bus признаём явно |
| Подмена процесса между проверкой и выдачей | pidfd вместо PID там, где есть systemd; полностью не решается — фиксируем в документации |
| Подмена шифротекста провайдером | Подпись `.gpg-id`; для age — подписанный индекс; git — подписанные коммиты |
| Откат к старой версии | git-история; для облаков — якорь последнего rev в state.db + предупреждение при регрессе |
| Кража ноутбука | Аппаратный ключ (§3), tomb закрыт, TTL агента |
| Вредоносный плагин | Манифест разрешений, явный грант на `decrypt`, пиннинг хеша, `plugin audit` (§4.2) |
| Секреты в swap/core | mlock best-effort, `RLIMIT_CORE=0`, зануление буферов, tmpfs для coffin |
| Секреты в истории шелла | Ввод только с TTY/stdin |
| Утечка через конфликт-файлы | `.conflict-*` шифруются теми же получателями |
| Форензика после закрытия tomb | `shred` + tmpfs; на SSD с wear-leveling гарантий нет — говорим прямо |

Вне модели: скомпрометированная ОС, кейлоггеры, злонамеренный получатель (выданный однажды
доступ отзывается только `reencrypt` + ротацией, старые копии уже утекли).

---

## 11. Раскладка кода

```
cmd/binpass/            main, ldflags-версия
cmd/binpass-agent/
internal/
  cli/                  cobra-команды, одна на файл, без бизнес-логики
  tui/                  bubbletea
  config/               viper: YAML + ENV + флаги
pkg/
  store/                фасад: Get/Set/List/Move/Remove/Reencrypt
  secret/               парсер/сериализатор, поля, маскирование
  crypto/               Crypto: gpg (внешний бинарь), age; recipients
  identity/             источники ключей, age-plugin протокол, агент-клиент
  otp/                  TOTP/HOTP, YubiKey OATH
  tomb/                 coffin | luks | sparsebundle
  sync/                 движок, VersionVector, конфликты, WAL
  remote/               Remote + git, rclone (drive|yandex|webdav|s3)
  plugin/               три уровня: exec, recipes, go-plugin; манифесты, гранты
  keystore/
    secretservice/      D-Bus объекты, DH-сессии, слепой индекс, политика доступа
    keychain/           macOS Security.framework
    wincred/            Windows CredRead/CredWrite, DPAPI
    integrations/       git, docker, ssh/sudo askpass, k8s, aws, netrc, exec
  importer/             9 форматов (KDBX, Bitwarden, 1Password, LastPass, Chrome, Firefox, Enpass, pass, gopass); Registry, Entry, Plan/WriteEntries, csvReadAll (BOM/encoding/multiline), NormalizePath/ValidatePath/DeduplicatePaths
  audit/                HIBP k-anonymity (5-char prefix, in-memory cache, noopHIBP для offline), zxcvbn strength, SHA-1 reuse detection, expiry (RFC 3339/ISO/European/relative), FormatHuman (severity grouping), JSON output, parallel decryption
  binary/               .b64 entries (gopass convention): Cat (streaming base64 decode), Sum (SHA-256), Store (base64 encode), DetectBinary, IsBinary
  pwgen/  clip/  tmpfile/
```

Каждый экспортированный элемент и каждый пакет — с godoc (`doc.go`), линтуется
`revive.exported` + `godot`.

---

## 12. Тестирование

* **Golden-тесты против настоящего pass**: в контейнере ставится `pass`, на одинаковом сторе
  прогоняется одна последовательность команд для обоих, сравниваются stdout, stderr, коды
  возврата и состояние дерева. Расхождение — падение сборки. Это то, что делает
  «совместим с pass» проверяемым утверждением.
* **Совместимость экосистемы**: смоук-сценарии для `passmenu`, `rofi-pass`, `browserpass-native`,
  `pass-git-helper`, QtPass. Результат — таблица поддержки в README.
* **Паритет с плагинами**: для каждого нативного аналога (§5) — тест «делает то же, что оригинал»
  на одинаковых входных данных, где оригинал устанавливается в контейнер.
* **Unit**, table-driven, `gomock` на `Crypto`/`Remote`/`Identity`/`Storage`. Цель 85%, gate 70%.
* **Fuzz**: парсер секретов, `otpauth://`, парсеры импорта (чужие форматы — самое хрупкое).
* **Property**: движок мержа — «ничего не теряется» + детерминизм при любом порядке аргументов.
* **Интеграционные** (`testcontainers`): bare git, WebDAV, MinIO, `rclone serve` как заглушка Drive.
  Сценарий: два клиента, оффлайн-правки, конфликт, разрешение.
* **Аппаратные ключи**: `age-plugin-*` мокаются через тестовый плагин, реализующий протокол;
  реальное железо — в отдельном ручном чек-листе перед релизом.
* **Tomb**: тесты на LUKS в привилегированном контейнере, coffin — везде.
* **Secret Service**: реальные клиенты против нашего демона в контейнере с dbus-daemon —
  `secret-tool`, `libsecret` через биндинги, Python `keyring`, git credential helper.
  Отдельно — соответствие спецификации: обе схемы `OpenSession`, `Prompt`, `Lock`/`Unlock`,
  алиас `default`, `replace` в `CreateItem`. Слепой индекс проверяется property-тестом:
  результат `SearchItems` совпадает с результатом поиска по расшифрованным атрибутам.
* **Интеграции**: docker credential helper, `git credential fill`, `aws credential_process`,
  `kubectl` exec-plugin — по фиксированным контрактам их протоколов.
* **E2E CLI**: `rogpeppe/go-internal/testscript`, сценарии обычными txt-файлами.
* Прогоны на всех трёх ОС — клипборд, права и пути ломаются именно там.

---

## 13. Стек

| Слой | Выбор |
|---|---|
| CLI | `spf13/cobra` + `spf13/pflag` |
| Конфиг | `spf13/viper`, приоритет: флаги > ENV > YAML > дефолты |
| Крипто | `filippo.io/age` (+ `agessh`, `plugin`), внешний `gpg`, `ProtonMail/go-crypto` как фолбэк |
| Аппаратные ключи | age-plugin протокол (`yubikey`, `fido2-hmac`, `se`, `tpm`), gpg-agent для smartcard |
| git | системный `git`, `go-git/go-git/v5` фолбэк |
| Облака | `rclone/rclone` — точечные импорты `drive`, `yandex`, `webdav`, `s3` |
| OAuth | `golang.org/x/oauth2` + локальный редирект / device-flow |
| Плагины | exec + `hashicorp/go-plugin` (gRPC), опц. `tetratelabs/wazero` для WASM |
| D-Bus | `godbus/dbus/v5` — чистый Go, без libdbus и CGO |
| Keychain / WinCred | `keybase/go-keychain`, прямые вызовы `advapi32`/`crypt32` через `golang.org/x/sys/windows` |
| Локальное состояние | `go.etcd.io/bbolt` |
| Хеш | `zeebo/blake3` |
| TUI | `charmbracelet/bubbletea` + `lipgloss` |
| Оценка паролей | `zxcvbn-go`, EFF-словари для diceware |
| Логи | `log/slog`, по умолчанию warn+ |
| Тесты | `testify`, `golang/mock`, `testcontainers-go`, `testscript` |
| Сборка | `goreleaser` (deb/rpm/apk/brew/scoop/AUR/winget), `golangci-lint`, `govulncheck` |

### Конфиг — `~/.config/binpass/config.yaml`

```yaml
store:
  dir: ~/.password-store
crypto:
  default: age                 # чем шифровать НОВЫЕ записи: age | gpg
  gpg: { binary: gpg, opts: [] }
  age:
    identity: ~/.local/share/binpass/identities.age
    plugins: [yubikey, fido2-hmac]
unlock:
  agent: { enabled: true, ttl: 10m }
  require_presence: false      # касание токена на каждую расшифровку
tomb:
  type: coffin                 # coffin | luks | sparsebundle
  auto_close: 1h
  close_on: [screenlock, suspend, logout]
clip: { timeout: 45s, restore_previous: true }
generate: { length: 25, symbols: true, words: 0 }
plugins:
  enabled: true
  allow_network: false         # глобальный запрет, перекрывает манифесты
secret_service:                # Linux
  enabled: true
  collection_path: secret-service
  takeover: refuse             # refuse | wait | replace — если имя на шине занято
  default_action: prompt       # allow | deny | prompt
  remember: 8h
  notify: on-access
  lock_on: [screenlock, suspend, idle]
remotes:
  default: origin
  origin: { type: git, url: "git@github.com:alice/pass.git", sign_commits: true }
  gdrive: { type: drive, folder: "binpass" }
  yadisk: { type: yandex, folder: "binpass" }
  work:   { type: webdav, url: "https://dav.example.com/pass" }
sync:
  auto: off                    # off | on-change | interval
  conflict: keep-both          # keep-both | interactive | prefer-remote | prefer-local
```

---

## 14. Дорожная карта

| Этап | Содержание | Критерий готовности |
|---|---|---|
| **M0** | Дерево, `crypto/gpg` + `crypto/age`, ядро CLI, `version` | Golden-тесты против pass зелёные |
| **M1** | `identity`: age-plugin протокол, YubiKey PIV, FIDO2, агент | `binpass identity test` проходит на реальном токене |
| **M2** | `otp`, `binary`, `audit`, `import/export`, `generate --words` | Паритет с pass-otp / pass-audit / pass-import подтверждён тестами. **Все пять компонентов реализованы:** otp (main), generate --words (main), binary (pkg/binary, 19 tests), audit (pkg/audit, 96.2%), import/export (pkg/importer, 89.5%, 9 форматов, e2e 43/43) |
| **M3** | Движок sync, state.db, VV, конфликты, remote `git` | Два клиента, оффлайн-конфликт, корректное разрешение |
| **M4** | rclone: Drive + Yandex с встроенным OAuth, WebDAV, S3, locking | Интеграционные тесты на всех транспортах |
| **M5** | `tomb`: coffin везде, LUKS на Linux, sparsebundle на macOS | Автозакрытие по screenlock работает на трёх ОС |
| **M6** | Система плагинов: три уровня, манифесты, гранты, реестр | Внешний плагин ставится и работает по документации |
| **M6.5** | Secret Service: D-Bus, DH-сессии, слепой индекс, ACL, импорт из gnome-keyring | `secret-tool` и Chrome работают против binpass; gnome-keyring отключён |
| **M6.6** | Keychain/WinCred, `exec`, credential helpers (git, docker, k8s, aws) | Интеграции проходят контрактные тесты |
| **M7** | TUI, `update`/`rotate`/рецепты, `history`, `doctor`, `menu` | — |
| **M8** | Покрытие ≥70%, man-страницы, goreleaser, пакеты | Релиз |

Критический путь — **M3**. Синхронизация с разрешением конфликтов — единственная часть,
где ошибка в модели данных означает переписывание, а не доработку. Всё остальное аддитивно.

---

## 15. Что решить до старта

1. **Дефолтная крипта — age или GPG?** В конфиге стоит `age`, и для нового пользователя это
   правильно (проще, аппаратные плагины). Но тогда неизменённый `pass` не увидит новые записи,
   потому что хардкодит `.gpg`. Вопрос: важнее «поставил рядом с pass» или «переехал начисто»?
2. **Уровень 3 плагинов (go-plugin) — сразу или после M6?** Уровни 1–2 закрывают 90% кейсов
   за 10% усилий. gRPC-плагины нужны только для своих транспортов и типов секретов.
3. **Реестр плагинов** — заводим свой (модерация, подписи, ответственность) или только
   установка по URL?
4. **Windows и tomb.** Coffin работает, LUKS — нет. VHDX+BitLocker требует Pro-редакцию.
   Достаточно coffin или нужен третий бэкенд?
5. **`--obfuscate`** — делаем ли вообще, если tomb/coffin решает ту же задачу лучше
   и без потери совместимости?
6. **Объём стора для проектирования дельта-синхронизации.** 200 записей и 5000 — разные
   стратегии на Drive из-за rate limits.
7. **Secret Service и синхронизация.** Chrome и NetworkManager пишут в keystore постоянно.
   При `sync.auto: on-change` это означает коммит в git на каждое обновление cookie-ключа.
   Варианты: отдельная политика синхронизации для `secret-service/`, дебаунс, или исключение
   этого поддерева из автосинка по умолчанию. Склоняюсь к дебаунсу в 30–60 с.
8. **Дефолт политики доступа.** `prompt` безопаснее, но первый запуск Chrome выдаст серию
   диалогов и человек нажмёт «разрешить всё». `allow` с журналом и уведомлениями честнее
   по отношению к реальному поведению пользователей. Что выбираем?
9. **Ключ слепого индекса** живёт в агенте. Значит при заблокированном сторе поиск невозможен
   и любой `SearchItems` порождает Prompt. Приемлемо, или нужен отдельный «поисковый» режим,
   когда индексный ключ кешируется дольше, чем ключ расшифровки?
