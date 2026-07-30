# binpass — архитектура

**Что это:** drop-in замена `pass`/`gopass` с шифрованием `age` вместо GPG, встроенным TOTP/HOTP,
поддержкой типизированных секретов (логин/пароль, текст, бинарь, банковские карты) и синхронизацией
через три взаимозаменяемых бэкенда: собственный сервер, git, облака через rclone.

* Язык: Go 1.23+, `CGO_ENABLED=0`, кросс-компиляция под linux/darwin/windows × amd64/arm64.
* Бинарники: `binpass` (клиент, CLI+TUI), `binpassd` (сервер синхронизации).
* Лицензия зависимостей: age (BSD-3), rclone (MIT), go-git (Apache-2.0) — всё совместимо.

---

## 0. Ключевые архитектурные решения (TL;DR)

| # | Решение | Почему |
|---|---------|--------|
| 1 | **Один `Remote`-интерфейс на все бэкенды** — сервер, git, rclone. Движок синхронизации один | Не плодим три разные логики конфликтов. Сервер — не привилегированный, а частный случай |
| 2 | **Content-addressed объекты + подписанный манифест** | Дешёвые переименования, дедупликация, целостность, работает поверх тупого блоб-стора (S3/Drive) и поверх git |
| 3 | **Сервер видит только шифротекст**, ключей не имеет | ТЗ отдаёт «обеспечение безопасности» на откуп исполнителю → E2E-шифрование сильнее любой TLS-схемы |
| 4 | **Пароль аккаунта ≠ ключ шифрования**, но вводится один | HKDF от мастер-фразы даёт две независимые ветки: auth-секрет уходит на сервер, ключевая — никогда |
| 5 | **Манифест подписывается ключом хранилища** (Ed25519, лежит в самом хранилище под age) | Защита от rollback/подмены со стороны сервера или облака: recipients-ключи публичны, шифротекст может сфабриковать кто угодно |
| 6 | **gRPC поверх TLS 1.3 — основной транспорт; grpc-gateway отдаёт REST-фасад и OpenAPI; resty — резервный REST-транспорт** | Закрывает сразу два необязательных пункта ТЗ (бинарный протокол + Swagger), а REST-путь остаётся для окружений, где ломают HTTP/2 |
| 6a | **Сервер по раскладке `evrone/go-clean-template`** | Готовая Clean Architecture: зависимости внутрь, usecase не знает ни про gin, ни про PostgreSQL → транспорт и хранилище меняются без правки бизнес-логики |
| 6b | **Конфиг: viper, YAML + ENV + флаги cobra**, единый для клиента и сервера | Один механизм на оба бинаря; в Docker — чистый ENV, локально — YAML, в CI — флаги |
| 7 | **git/rclone/WebDAV — только на клиенте** (требование заказчика) | Сервер остаётся тонким: auth + блобы + CAS-манифест |
| 8 | **Version vector на запись**, конфликт → обе копии на диск | Мержить шифротекст нельзя; молча терять данные пароль-менеджеру нельзя тем более |

---

## 1. Границы совместимости

### Что делаем drop-in

Layout хранилища и семантика команд `pass`, поведение `passage` в части age, расширенные команды `gopass`,
формат OTP как у `pass-otp`.

```
$BINPASS_STORE_DIR         (default: ~/.password-store, fallback ~/.passage/store)
├── .age-recipients               # список получателей (age1..., ssh-ed25519 AAAA...)
├── .gpg-id                       # читаем только для миграции
├── .binpass/
│   ├── config.yaml               # неконфиденциальный конфиг стора
│   ├── signing.key.age           # Ed25519 ключ подписи манифеста
│   ├── index.age                 # опц.: карта имён при обфускации
│   └── state/
│       ├── manifest.local.json   # последний известный манифест
│       ├── base.json             # база для 3-way (общий предок)
│       └── journal.wal           # WAL незакоммиченных операций
├── github.com/
│   ├── alice.age
│   └── bob.age
└── bank/
    ├── .age-recipients           # переопределение получателей для поддерева
    └── tinkoff-black.age
```

* Расширение `.age` (как в passage), но `.gpg` читается прозрачно, если найден бинарь `gpg` — нужно для `binpass migrate`.
* `.age-recipients` наследуется вниз по дереву, ближайший побеждает — как `.gpg-id` в pass.
* `BINPASS_*` env-переменные дублируют `PASSWORD_STORE_*`, чтобы существующие скрипты и `passmenu`/`rofi-pass` не переписывать.

### Формат секрета

Первая строка — пароль (правило pass). Дальше — либо `key: value`, либо MIME-подобный
типизированный блок (совместим с `GOPASS-SECRET-1.0`):

```
hunter2
otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&period=30
url: https://github.com
username: alice
comment: рабочий аккаунт
```

Типизированный вариант для карт и произвольных данных ТЗ:

```
BINPASS-SECRET-1.0
Type: card
Bank: Тинькофф
Number: 5536 9138 XXXX XXXX
Holder: ALICE IVANOVA
Expires: 09/29
CVV: 123
X-Meta-Note: основная зарплатная

<произвольный текст после пустой строки>
```

* `Type`: `login` (default) | `text` | `binary` | `card` | `otp`.
* Любые `X-*` заголовки — та самая «произвольная текстовая метаинформация» из ТЗ, применима ко всем типам.
* Бинарь: gopass-совместимо кладём как `name.b64.age` (base64 внутри) для мелких файлов; для
  > 1 МиБ — чанкованное хранение (см. §5.3), в секрете остаётся только манифест чанков.

---

## 2. Криптография

### 2.1 Шифрование данных

`filippo.io/age`. Получатели поддерживаются все, что умеет age:

| Тип | Пакет | Сценарий |
|-----|-------|----------|
| X25519 (`age1...`) | `age` | базовый |
| ssh-ed25519 / ssh-rsa | `age/agessh` | переиспользование существующих ключей, deploy-ключи |
| scrypt (парольная фраза) | `age` | одиночный юзер без файла ключа |
| age-plugin-yubikey / -fido2 / -se | `age/plugin` | аппаратный второй фактор к самому хранилищу |

Мульти-recipient «из коробки» — это и есть шаринг стора между устройствами и людьми:
добавил `age1...` нового устройства в `.age-recipients`, сделал `binpass reencrypt`, синхронизировал.

### 2.2 Мастер-фраза и разделение ключей

Пользователь помнит одну фразу. Из неё:

```
MK  = Argon2id(passphrase, salt=user_salt, m=256MiB, t=3, p=4)   // 32 байта, только в памяти клиента
AUTH_SECRET = HKDF-SHA256(MK, info="binpass/auth/v1")            // уходит на сервер (сервер хранит Argon2id от него)
IDENT_KEY   = HKDF-SHA256(MK, info="binpass/identity/v1")        // никогда не покидает клиент
```

`IDENT_KEY` разворачивает локальный `identities.age` (scrypt-обёртка над X25519-ключом устройства).
Сервер, даже полностью скомпрометированный, получает только `Argon2id(AUTH_SECRET)` — до данных
это не приближает. `user_salt` выдаётся сервером при регистрации и синхронизируется как публичное поле.

Если пользователь предпочитает файл ключа / YubiKey — ветка `IDENT_KEY` не используется вовсе,
пароль аккаунта задаётся отдельно.

### 2.3 Целостность и защита от отката

Проблема: recipients-ключи публичны, значит любой (включая скомпрометированный сервер)
может создать валидный `.age`, который клиент расшифрует. Плюс сервер может подсунуть старую версию манифеста.

Решение: **манифест подписан** Ed25519-ключом хранилища (`.binpass/signing.key.age`, доступен
всем, кто может читать стор).

```go
type SignedManifest struct {
    Manifest   []byte // canonical JSON
    Signature  []byte // Ed25519 над (Generation || StoreID || sha256(Manifest))
    PublicKey  []byte
}
```

Клиент отвергает манифест, если: подпись не сходится, `Generation` меньше локально известной,
или `StoreID` не тот. Объекты, которых нет в подписанном манифесте, не расшифровываются вообще.

### 2.4 Агент

`binpass-agent` (или встроенный демон, поднимаемый по требованию): unix-socket `$XDG_RUNTIME_DIR/binpass/agent.sock`,
на Windows — named pipe. Держит расшифрованную identity `BINPASS_AGENT_TTL` (default 600 c),
умеет forget по SIGHUP и по блокировке экрана. Секреты в памяти — `memguard`/`mlock` best-effort,
явное зануление буферов, отключение core dumps.

---

## 3. MFA: TOTP / HOTP

* `pkg/otp`, RFC 6238 / RFC 4226, алгоритмы SHA1/SHA256/SHA512, digits 6–8, произвольный period/skew.
* Источник — URI `otpauth://` в теле секрета (совместимо с `pass-otp`) или отдельный секрет `Type: otp`.
* Команды: `binpass otp <name>` (код + остаток времени), `-c` в буфер, `--qr` для переноса на телефон,
  `binpass otp append <name>` для добавления URI к существующей записи.
* **HOTP-счётчик — единственное поле с автоинкрементом**, и это конфликтная точка при синхронизации.
  Счётчик выносится из шифротекста в отдельный объект `<path>#hotp` с правилом мержа `max(a, b)`
  (проскочить вперёд безопасно, откатиться — нет). Правило зашито в движок синхронизации как
  специальный merger, см. §6.3.
* TUI-режим `binpass otp --watch` с обратным отсчётом.

---

## 4. Раскладка кода

```
cmd/
  binpass/            main + ldflags-версия
  binpassd/           сервер
  binpass-agent/
internal/
  cli/              cobra-команды, ровно 1:1 с поверхностью pass/gopass; pflag ↔ viper binding
  tui/              bubbletea (необязательный пункт ТЗ)
  config/           viper: загрузка YAML + ENV + флагов, валидация
pkg/
  store/            фасад: Get/Set/List/Move/Remove/Reencrypt — вся бизнес-логика стора
  secret/           парсер/сериализатор формата, типы login|text|binary|card|otp
  otp/              TOTP/HOTP
  crypto/           interface Crypto: age (осн.), gpg (только чтение, миграция)
  identity/         поиск/разблокировка identity, agent-клиент, plugins
  storage/          локальное дерево: fs (atomic write, fsync, 0600)
  remote/           interface Remote + реализации:
    server/         gRPC-клиент (основной) + resty-транспорт REST (fallback), выбор из конфига
    git/            git-бинарь + go-git fallback
    rclone/         S3, WebDAV, Google Drive, Yandex.Disk, …
  sync/             движок: манифест, version vectors, конфликты, WAL
  manifest/         структуры, канонизация, подпись
  pwgen/  clip/  tmpfile/  audit/  fsck/
```

Сервер (`binpassd`) — отдельный модуль по раскладке `evrone/go-clean-template`:

```
cmd/binpassd/main.go          конфиг → app.Run(cfg), больше ничего
config/
  config.go                 структуры + viper-загрузка + validator
  config.yaml               дефолты, без секретов
internal/
  app/
    app.go                  DI-сборка: postgres → repo → usecase → controllers → httpserver
    migrate.go              автомиграции (build-tag migrate)
  entity/                   User, Device, Session, Object, Manifest — чистые типы, нулевые зависимости
  usecase/
    contracts.go            ВСЕ интерфейсы (UserRepo, ManifestRepo, ObjectRepo, BlobStore, TokenIssuer)
    auth.go                 AuthUseCase: register/login/refresh/enroll/revoke
    vault.go                VaultUseCase: manifest CAS, objects, events
    repo/
      persistent/           PostgreSQL-реализации (pgx)
      blob/                 fs / s3 реализация BlobStore
  controller/
    grpc/v1/                основной контроллер: Auth, Vault, интерцепторы
    http/v1/                grpc-gateway + gin для /healthz, /metrics, /swagger
api/proto/v1/               *.proto — единственный источник правды по контракту
gen/                        сгенерённое: pb.go, gateway, openapiv2 (в репо, buf generate)
migrations/                 goose/golang-migrate
docs/                       swaggo → swagger.json + Swagger UI
integration-test/           testcontainers, полный цикл через реальный HTTP
pkg/
  httpserver/  grpcserver/  logger/  postgres/  argon2/  jwt/
```

**Правило зависимостей:** `controller → usecase → entity`, `repo → usecase (через интерфейсы)`.
Ни один импорт не идёт наружу. `usecase` не знает слов `gin`, `pgx`, `resty` — за счёт этого
и появляется возможность подключить gRPC-контроллер вторым, не тронув бизнес-логику.

Каждый экспортированный тип/функция/переменная и каждый пакет — с godoc-комментарием
(жёсткое требование ТЗ; линтуется `revive` + `godot` в CI).

---

## 5. Модель данных синхронизации

### 5.1 Объекты

Всё, что хранится, — иммутабельный блоб, адресуемый по хешу **шифротекста**:

```
ObjectID = "b3:" + hex(blake3-256(ciphertext))
```

Плюсы: сервер/облако не может подменить содержимое незаметно; переименование = изменение только манифеста;
дедупликация между версиями; повторная отправка идемпотентна.

### 5.2 Манифест

```go
// Manifest — полное состояние хранилища на момент Generation.
type Manifest struct {
    Version    int                 `json:"v"`
    StoreID    string              `json:"store_id"`    // UUID, создаётся при init
    Generation uint64              `json:"gen"`         // монотонный счётчик коммитов
    Entries    map[string]Entry    `json:"entries"`     // ключ — логический путь "github.com/alice"
    Devices    map[string]Device   `json:"devices"`     // для аудита и отзыва
    UpdatedAt  time.Time           `json:"updated_at"`
}

// Entry — одна запись хранилища.
type Entry struct {
    Object   ObjectID          `json:"oid,omitempty"`    // для мелких секретов
    Chunks   []ObjectID        `json:"chunks,omitempty"` // для бинарей
    Size     int64             `json:"size"`
    Kind     Kind              `json:"kind"`             // secret | binary | counter
    Version  VersionVector     `json:"vv"`               // {deviceID: counter}
    Deleted  bool              `json:"deleted,omitempty"`// tombstone
    DeletedAt *time.Time       `json:"deleted_at,omitempty"`
}

// VersionVector — причинность правок между устройствами.
type VersionVector map[string]uint64
```

Манифест целиком — один объект, коммитится атомарно через compare-and-swap по `Generation`.
Это даёт транзакционность мультифайловых операций (`mv` каталога, `reencrypt` всего стора)
на любом бэкенде, включая тупой S3.

Tombstone'ы живут `retention` (default 90 дней), потом вычищаются `binpass gc` — иначе манифест растёт вечно.

### 5.3 Большие бинарники

Чанкование FastCDC (~1 МиБ средний чанк), каждый чанк шифруется отдельно и адресуется по хешу.
Даёт инкрементальную дозагрузку и дедупликацию между версиями файла. Заливка/скачивание —
gRPC-стримами по чанку на сообщение (без буферизации файла в памяти),
у rclone — обычными multipart-загрузками.

Утечка метаданных: размер и число чанков видны. Кому критично — `padding: true` в конфиге,
округление до степени двойки.

### 5.4 Обфускация имён (опционально)

По умолчанию пути в открытом виде — цена совместимости с pass. Флаг `obfuscate: true`:
`storedPath = base32(HMAC-SHA256(index_key, logicalPath))`, карта имён — в `.binpass/index.age`.
Совместимость с `pass` при этом теряется, о чём предупреждаем при `init --obfuscate`.

---

## 6. Движок синхронизации

### 6.1 Интерфейс remote

```go
// Remote — транспорт синхронизации. Реализуется сервером, git и rclone одинаково.
type Remote interface {
    Name() string
    Caps() Caps // AtomicCAS, History, Watch, PartialFetch

    Manifest(ctx context.Context) (*manifest.Signed, error)
    CommitManifest(ctx context.Context, m *manifest.Signed, expect uint64) error // ErrConflict при рассинхроне

    HasObjects(ctx context.Context, ids []ObjectID) (map[ObjectID]bool, error)
    PutObject(ctx context.Context, id ObjectID, r io.Reader) error
    GetObject(ctx context.Context, id ObjectID) (io.ReadCloser, error)
    DeleteObjects(ctx context.Context, ids []ObjectID) error // GC

    Watch(ctx context.Context) (<-chan Event, error) // опц.
    Close() error
}
```

Реализации бэкендов:

| | Сервер | git | rclone |
|---|---|---|---|
| Объекты | таблица + blobstore | `objects/ab/cdef…` в репозитории | ключи в бакете/папке |
| Манифест | строка в PG, CAS по generation | `manifest.json` в коммите | `manifest.json` + условная запись |
| Атомарность CAS | транзакция БД | атомарность `push` (non-fast-forward отклоняется) | ETag/If-Match у S3; у Drive/WebDAV — lock-файл + retry |
| История | таблица `manifests` | сам git | нет (только N последних манифестов) |
| Watch | серверный gRPC-стрим | нет (polling) | нет (polling) |

`Caps()` честно сообщает движку, чего бэкенд не умеет, — дальше деградация: нет `Watch` → polling
с интервалом; нет истинного CAS → advisory-lock + verify-after-write.

### 6.2 Цикл синхронизации

```
1. WAL: локальные изменения уже записаны в journal.wal (crash-safe)
2. remoteM  := remote.Manifest()      → проверка подписи и монотонности generation
3. baseM    := state/base.json        (общий предок)
4. localM   := построить из дерева + WAL
5. merged, conflicts := merge3(baseM, localM, remoteM)
6. push: объекты, которых нет на remote (HasObjects → PutObject)
7. remote.CommitManifest(merged, expect=remoteM.Generation)
      ErrConflict → goto 2 (backoff, до N раз)
8. pull: GetObject для новых записей → atomic write в дерево
9. state/base.json := merged;  WAL очищается
10. conflicts → на диск как отдельные записи + отчёт пользователю
```

Порядок «сначала объекты, потом манифест» гарантирует, что манифест никогда не ссылается
на несуществующий блоб. Обратный порядок при удалении: сначала манифест, потом GC блобов.

### 6.3 Разрешение конфликтов

Сравниваем version vectors записи:

| Ситуация | Действие |
|---|---|
| `VV_local == VV_remote` | ничего |
| `VV_local` доминирует | push |
| `VV_remote` доминирует | pull |
| Одинаковый `ObjectID`, разные VV | слить VV, данные не трогать |
| **Расходятся** (concurrent) | конфликт |
| Расходятся, `Kind == counter` (HOTP) | `max(a,b)`, автоматически |
| Расходятся, delete vs edit | побеждает edit, tombstone снимается, юзеру warning |

Конфликт по умолчанию: побеждает удалённая версия в основном пути, локальная сохраняется как
`github.com/alice.conflict-<device>-20260730T142233.age`, в конце `binpass sync` — сводка.
Ничего не теряется молча — принцип Syncthing.

Опция `--merge=interactive`: обе версии расшифровываются, показывается пофайловый diff
по полям секрета (пароль маскируется), пользователь выбирает. Полностью автоматический
field-wise merge сознательно **не** делаем по умолчанию — слишком легко получить франкенштейн-секрет.

### 6.4 Оффлайн и отказы

* Всё работает без сети: `Set/Get/Remove` пишут в дерево + WAL, `sync` догоняет позже.
* WAL реиграется при старте, если процесс упал между записью файла и обновлением состояния.
* Локальные записи всегда атомарны: `write tmp → fsync → rename → fsync(dir)`, права 0600/0700.

---

## 7. Сервер синхронизации (`binpassd`)

Покрывает ровно то, что требует ТЗ: регистрация, аутентификация, авторизация, хранение приватных
данных, синхронизация между несколькими клиентами одного владельца, выдача данных по запросу.
Git/rclone/WebDAV в сервере отсутствуют — это чисто клиентские бэкенды.

### 7.1 Протокол

**gRPC поверх TLS 1.3** — основной транспорт и одновременно «бинарный протокол» из необязательных
пунктов ТЗ. Рядом `grpc-gateway` поднимает REST-фасад из тех же `.proto` и генерит
`openapiv2/swagger.json` (ещё один необязательный пункт). Контракт живёт в `api/proto/v1`,
кодогенерация — `buf generate`, сгенерённое коммитится в репозиторий.

```proto
service Auth {
  rpc Register     (RegisterRequest)  returns (TokenPair);   // login + auth_secret → tokens + user_salt
  rpc Login        (LoginRequest)     returns (TokenPair);
  rpc Refresh      (RefreshRequest)   returns (TokenPair);
  rpc Logout       (LogoutRequest)    returns (google.protobuf.Empty);
  rpc EnrollDevice (EnrollRequest)    returns (Device);
  rpc ListDevices  (google.protobuf.Empty) returns (DeviceList);
  rpc RevokeDevice (RevokeRequest)    returns (google.protobuf.Empty);
}

service Vault {
  rpc GetManifest    (google.protobuf.Empty)   returns (SignedManifest);
  rpc CommitManifest (CommitRequest)           returns (CommitResponse);
  rpc HasObjects     (ObjectIDs)               returns (ObjectPresence);
  rpc PutObject      (stream PutObjectChunk)   returns (PutObjectResponse);
  rpc GetObject      (GetObjectRequest)        returns (stream ObjectChunk);
  rpc Watch          (WatchRequest)            returns (stream ChangeEvent);
}

message CommitRequest {
  SignedManifest manifest = 1;
  uint64 expect_generation = 2;   // CAS: несовпадение → FAILED_PRECONDITION
}

message PutObjectChunk {
  oneof payload {
    ObjectHeader header = 1;      // oid + total_size, первым сообщением
    bytes        data   = 2;      // ≤ 1 MiB на сообщение
  }
}
```

Правила отображения ошибок (единые для gRPC и REST через gateway):

| Домен | gRPC | HTTP |
|---|---|---|
| Гонка при коммите манифеста | `FAILED_PRECONDITION` | 412 |
| Объект не найден | `NOT_FOUND` | 404 |
| Токен протух / невалиден | `UNAUTHENTICATED` | 401 |
| Чужой ресурс | `PERMISSION_DENIED` | 403 |
| Логин занят | `ALREADY_EXISTS` | 409 |
| Превышена квота / размер объекта | `RESOURCE_EXHAUSTED` | 429 |

`Watch` — серверный стрим, даёт мгновенное распространение изменений между устройствами
(сценарий ТЗ «синхронизация между несколькими авторизованными клиентами одного владельца»).
Fallback — polling с интервалом из конфига.

**Клиент (`pkg/remote/server`).** Два транспорта за одним интерфейсом, выбор через
`remotes.server.transport`:

* `grpc` (по умолчанию) — `grpc-go` с интерцепторами:
  * unary+stream auth-интерцептор подставляет `authorization: Bearer <access>`;
  * при `UNAUTHENTICATED` — прозрачный refresh **под single-flight** и один повтор
    (иначе десяток параллельных 401 сожгут цепочку ротации и выкинут пользователя);
  * retry-интерцептор с backoff+jitter на `UNAVAILABLE`/`RESOURCE_EXHAUSTED`, уважает `retry-after`;
  * keepalive, `WithBlock` только на явном `binpass login`, TLS 1.3, опц. pinning по SPKI;
  * стриминг блобов чанками по 1 МиБ — файл на 500 МБ не попадает в heap.
* `rest` — `resty` поверх gateway-эндпоинтов, для окружений с прокси, которые ломают HTTP/2.
  Тот же набор операций, CAS через `If-Match`/`412`, ретраи и refresh — в `OnBeforeRequest`/`OnAfterResponse`.

REST-эндпоинты (генерятся из proto-аннотаций, они же в Swagger):

```
POST   /api/v1/auth/register | /login | /refresh | /logout
GET    /api/v1/devices        POST /api/v1/devices        DELETE /api/v1/devices/{id}
GET    /api/v1/vault/manifest                 → ETag: "<generation>"
PUT    /api/v1/vault/manifest                 If-Match: "<generation>" → 412 при гонке
POST   /api/v1/vault/objects:check
PUT|GET /api/v1/vault/objects/{oid}           octet-stream, стрим
GET    /healthz  /readyz  /metrics  /swagger/index.html
```

### 7.1a Слои сервера

| Слой | Пакет | Знает про | Пример |
|---|---|---|---|
| Entity | `internal/entity` | ничего | `User`, `Device`, `Manifest`, `Object`, `ErrGenerationMismatch` |
| UseCase | `internal/usecase` | только entity + свои интерфейсы | `VaultUseCase.CommitManifest(ctx, userID, m, expectGen)` |
| Repo | `internal/usecase/repo` | pgx, S3 | `ManifestRepo.InsertIfAbsent(...)` |
| Controller | `internal/controller/grpc/v1` | grpc, protobuf-DTO, коды статусов | `CommitManifest` → мапит `expect_generation`, зовёт usecase |
| App | `internal/app` | всё, только для сборки | DI, миграции, graceful shutdown |

Интерфейсы объявляются **в `usecase/contracts.go`** (потребителем), а не в репозитории —
это то, что делает usecase тестируемым чистыми моками, позволяет подменить PostgreSQL
на что угодно и держать два транспорта (gRPC и REST) поверх одной бизнес-логики.

### 7.2 Аутентификация и авторизация

* Регистрация: клиент шлёт `login` + `AUTH_SECRET` (см. §2.2). Сервер хранит `Argon2id(AUTH_SECRET)`
  и выдаёт `user_salt`. Пароль в открытом виде сервер не видит никогда.
* Access-token: JWT (Ed25519), TTL 15 мин, claims `sub`, `device_id`, `store_id`.
* Refresh-token: случайные 32 байта, хранится хешем, привязан к устройству, ротация при каждом
  использовании, детект переиспользования → отзыв всей цепочки.
* Авторизация: interceptor проверяет `user_id` из токена против владельца ресурса. Модель простая —
  один пользователь = одно хранилище; шаринг между людьми делается на уровне age-recipients,
  а не на уровне сервера. Это осознанно: сервер не должен знать, кто с кем чем делится.
* Rate limiting на `Login`/`Register` (token bucket по IP + по логину), защита от брутфорса.
* Опционально TOTP как второй фактор на вход в аккаунт — переиспользуем `pkg/otp`.

### 7.3 Хранилище сервера

PostgreSQL для метаданных + blobstore (локальная ФС или S3) для объектов.

```sql
users          (id, login UNIQUE, auth_hash, user_salt, created_at)
devices        (id, user_id, name, pubkey, created_at, last_seen_at, revoked_at)
refresh_tokens (id, device_id, token_hash, expires_at, used_at, revoked)
manifests      (user_id, generation, blob, signature, device_id, created_at,
                PRIMARY KEY (user_id, generation))
objects        (user_id, oid, size, storage_ref, created_at,
                PRIMARY KEY (user_id, oid))
object_refs    (user_id, oid, generation)   -- для GC по достижимости
audit_log      (id, user_id, device_id, action, ip, at)
```

CAS-коммит манифеста:

```sql
INSERT INTO manifests (user_id, generation, blob, signature, device_id)
VALUES ($1, $2 + 1, $3, $4, $5);   -- уникальный индекс по (user_id, generation) = гонка отсекается
```

Квоты на пользователя (объём/число объектов). GC: объекты, не достижимые ни из одного манифеста
за retention-окно, удаляются фоновым воркером.

### 7.4 Эксплуатация

Health/readiness пробы, `/metrics` (Prometheus), структурные логи (zap/slog) **без единого
байта пользовательских данных**, graceful shutdown, миграции (goose/golang-migrate),
Docker + docker-compose для локального запуска, конфиг через env/флаги/файл с приоритетом flags > env > file.

---

## 8. Конфигурация: YAML + ENV + флаги (viper)

Один механизм на оба бинаря. Приоритет строгий: **флаги cobra > переменные окружения > YAML-файл > дефолты в коде**.

```go
// config.Load читает YAML, накладывает ENV и флаги, валидирует результат.
func Load(cmd *cobra.Command) (*Config, error) {
    v := viper.New()
    v.SetConfigName("config")
    v.SetConfigType("yaml")
    v.AddConfigPath(userConfigDir())         // ~/.config/binpass  |  /etc/binpassd
    v.AddConfigPath(".")

    v.SetEnvPrefix("BINPASS")                // APASSD для сервера
    v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
    v.AutomaticEnv()                         // store.dir → BINPASS_STORE_DIR

    setDefaults(v)

    if err := v.BindPFlags(cmd.Flags()); err != nil { return nil, err }
    if err := v.ReadInConfig(); err != nil {
        if _, ok := err.(viper.ConfigFileNotFoundError); !ok { return nil, err }
    }

    var cfg Config
    if err := v.Unmarshal(&cfg); err != nil { return nil, err }
    return &cfg, validator.New().Struct(&cfg)   // go-playground/validator
}
```

### 8.1 Клиент — `~/.config/binpass/config.yaml`

```yaml
store:
  dir: ~/.password-store
  obfuscate_names: false
crypto:
  identity: ~/.config/binpass/identities.age
  agent:
    enabled: true
    ttl: 10m
clip:
  timeout: 45s
  restore_previous: true
generate:
  length: 24
  symbols: true
remotes:
  default: server
  server:
    url: https://vault.example.com
    timeout: 30s
    retry: 3
    transport: grpc        # grpc | rest
    events: stream         # stream | poll | off
    poll_interval: 60s
    tls:
      pin_sha256: ""
  git:
    url: git@github.com:alice/secrets.git
    binary: git            # git | go-git
    sign_commits: true
  gdrive:                  # любой remote из rclone.conf
    type: rclone
    rclone_remote: gdrive:binpass
sync:
  auto: on-change          # off | on-change | interval
  conflict: keep-both      # keep-both | interactive | prefer-remote | prefer-local
log:
  level: info
  format: text
```

Совместимость со скриптами вокруг `pass` — через явные алиасы, а не магию:

```go
v.BindEnv("store.dir", "BINPASS_STORE_DIR", "PASSWORD_STORE_DIR")
v.BindEnv("clip.timeout", "BINPASS_CLIP_TIME", "PASSWORD_STORE_CLIP_TIME")
v.BindEnv("generate.length", "BINPASS_GENERATED_LENGTH", "PASSWORD_STORE_GENERATED_LENGTH")
```

### 8.2 Сервер — `config/config.yaml`

```yaml
app:
  name: binpassd
  version: ""              # подставляется ldflags, в файле пусто
http:                      # grpc-gateway + health/metrics/swagger
  port: "8080"
  read_timeout: 10s
  write_timeout: 30s
  shutdown_timeout: 15s
grpc:
  port: "8081"             # основной транспорт
  max_recv_mib: 8          # чуть больше размера чанка
  keepalive: 30s
pg:
  pool_max: 20
  url: ""                  # ТОЛЬКО из ENV: BINPASSD_PG_URL
blob:
  driver: fs               # fs | s3
  fs_path: /var/lib/binpassd/blobs
  s3: { endpoint: "", bucket: "", region: "" }
auth:
  argon2: { memory_mib: 256, time: 3, threads: 4 }
  access_ttl: 15m
  refresh_ttl: 720h
  jwt_private_key: ""      # ТОЛЬКО из ENV/секрет-файла
limits:
  max_object_size: 100MiB
  quota_per_user: 5GiB
  rate_login_per_min: 10
log:
  level: info
  format: json
```

### 8.3 Правила, которые нельзя нарушать

* **Секреты не живут в YAML.** `pg.url`, `jwt_private_key`, S3-credentials — только ENV или
  `*_FILE`-путь к секрет-файлу (docker/k8s secrets). Файл в репозитории содержит пустые плейсхолдеры,
  а `config.Load` падает на старте, если обязательное поле пустое (`validate:"required"`).
* **Никакого дампа конфига в лог целиком.** Метод `Config.Redacted()` возвращает копию
  с зачёркнутыми чувствительными полями — только он и логируется.
* **`viper.WatchConfig` — точечно.** Hot-reload разрешён только для `log.level` и лимитов;
  перечитывать на лету DSN или ключи подписи — источник трудновоспроизводимых багов.
* **В Docker — чистый ENV**, YAML не монтируется. В `docker-compose.yml` весь конфиг виден в одном месте.
* Клиентский `config.yaml` создаётся `binpass init` с правами 0600, каталог — 0700.

---

## 9. Клиентские бэкенды

### 8.1 git

```
binpass sync --remote git
binpass git init git@github.com:alice/secrets.git
```

* Основной путь — вызов системного `git` (работают credential helpers, ssh-agent, подпись коммитов,
  корпоративные прокси). Fallback на `go-git` там, где бинаря нет.
* Репозиторий хранит `objects/` + `manifest.json`; истории коммитов достаточно для отката.
* `.gitattributes`: `*.age binary`, кастомный merge-driver, который вместо мержа шифротекста
  зовёт `binpass merge-driver` → уходит в общий конфликт-резолвер §6.3.
* Не-fast-forward push = `ErrConflict` для движка, дальше стандартный retry-цикл.
* Совместимость: обычный `pass git`-стор (файлы в дереве, без `objects/`) читается в legacy-режиме.

### 8.2 rclone (S3, WebDAV, Google Drive, Yandex.Disk, …)

Подключаем как библиотеку, а не как бинарь:

```go
import (
    _ "github.com/rclone/rclone/backend/drive"
    _ "github.com/rclone/rclone/backend/s3"
    _ "github.com/rclone/rclone/backend/webdav"
    _ "github.com/rclone/rclone/backend/yandex"
    "github.com/rclone/rclone/fs"
    "github.com/rclone/rclone/fs/operations"
)
```

* Импортируем **точечно** нужные бэкенды, не `backend/all` — иначе бинарь распухает на десятки МБ.
  Build-теги `rclone_full` для сборки со всем набором.
* Конфиг берём из существующего `~/.config/rclone/rclone.conf` (если есть) либо из
  `.binpass/remotes.age` — OAuth-токены Google/Yandex это чувствительные данные,
  в открытом виде их не держим.
* CAS эмулируется: S3 — `If-Match` по ETag; Drive/WebDAV — lock-объект `manifest.lock` с TTL,
  запись, чтение-проверка. Честно помечаем в `Caps()` как `WeakCAS` и добавляем verify-after-write.
* Для Drive/Yandex учитываем rate limits → backoff с jitter, батчинг мелких объектов.

### 8.3 Несколько remote одновременно

`config.yaml` разрешает список: например, сервер как основной + git как резервный.
`binpass sync` проходит их последовательно, `binpass sync --remote=all` — по всем.
Манифест один и тот же, generation общий, так что бэкенды взаимно догоняются.

---

## 10. Поверхность CLI

```
binpass init [--recipient age1... | --identity file | --yubikey]
binpass insert [-m|--multiline] [-f] <name>
binpass show [-c[n]] [--field=url] [--qr] <name>
binpass edit <name>                     # правка в $EDITOR через tmpfs-файл
binpass generate [-n] [-c] <name> [len]
binpass rm|mv|cp|find|grep|ls
binpass otp [-c] [--watch] <name> ; binpass otp append <name> <uri>
binpass binary cat|copy|move|sum <name>
binpass card add|show <name>            # типизированный ввод: номер/держатель/срок/CVV
binpass recipients add|remove|list ; binpass reencrypt
binpass sync [--remote=NAME|all] [--dry-run] ; binpass conflicts list|resolve
binpass remote add server|git|rclone ...
binpass login|logout|register|devices [revoke]
binpass migrate --from=pass|gopass      # GPG → age, дерево переносится 1:1
binpass fsck ; binpass gc ; binpass audit   # аудит: слабые/переиспользованные пароли, HIBP k-anonymity
binpass tui
binpass version                         # версия, дата сборки, коммит, Go-версия, ОС/арх
binpass completion bash|zsh|fish|powershell
```

Версия и дата сборки (требование ТЗ) — через ldflags, без CGO:

```
go build -trimpath -ldflags="\
  -X main.version=$(git describe --tags) \
  -X main.commit=$(git rev-parse --short HEAD) \
  -X main.buildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" ./cmd/binpass
```

Дерево команд — `cobra`, каждая команда в отдельном файле `internal/cli/<cmd>.go`,
глобальные флаги `--config`, `--store`, `--remote`, `--log-level` привязаны к viper через
`BindPFlags` в `PersistentPreRunE`. Команды не содержат бизнес-логики: парсинг флагов →
вызов `pkg/store`/`pkg/sync` → форматирование вывода. Это делает возможным TUI и будущий
демон поверх той же логики.

Кросс-платформенность: пути через `os.UserConfigDir`, буфер обмена — `xclip`/`wl-copy`/`pbcopy`/
WinAPI с автоочисткой через N секунд (и восстановлением прежнего содержимого),
`edit` — во временный файл в tmpfs (Linux) / `os.CreateTemp` c 0600 и явным затиранием (Win/macOS).

---

## 11. Модель угроз

| Угроза | Митигация |
|---|---|
| Компрометация сервера/облака | E2E: только шифротекст. Ключей на сервере нет физически |
| Подмена шифротекста (recipients публичны) | Подписанный манифест, объекты вне манифеста игнорируются |
| Rollback к старому состоянию | Монотонный `Generation` + локальный якорь последней виденной версии |
| Утечка имён секретов | Известное ограничение pass; опция обфускации имён (§5.4) |
| Утечка размеров | Опциональный паддинг чанков |
| Брутфорс аккаунта | Argon2id (m=256MiB), rate limiting, опц. TOTP-2FA |
| Кража ноутбука | age-identity под scrypt/YubiKey, TTL агента, автолок |
| Секреты в swap/core | mlock best-effort, `RLIMIT_CORE=0`, зануление буферов |
| Секреты в истории шелла | чтение из stdin/TTY, никаких паролей аргументами |
| Утечка через логи | запрет полей с plaintext на уровне линтера + code review |
| MITM | TLS 1.3, опц. certificate pinning для собственного сервера |

Явно **вне** модели: скомпрометированная ОС клиента, кейлоггеры, злонамеренный recipient
(доступ, однажды выданный, отзывается только через `reencrypt` + ротацию — старые копии уже утекли).

---

## 12. Тестирование и документация

ТЗ требует ≥70% покрытия юнит-тестами и исчерпывающую документацию всего экспортированного.

* **Unit**: table-driven, `gomock` на интерфейсы `Remote`/`Crypto`/`Storage`. Цель 80%,
  gate в CI на 70% (`go test -coverprofile`, проверка порога скриптом).
* **Property/fuzz**: парсер секретов (`go test -fuzz`), FastCDC-чанкер, merge3 (инвариант:
  ничего не теряется, результат детерминирован при любом порядке аргументов).
* **Интеграционные**: `testcontainers-go` — PostgreSQL, MinIO (S3), локальный WebDAV,
  bare git-репозиторий во временной папке. Полный цикл: register → insert → sync →
  второй клиент → login → sync → show.
* **Конфликтные сценарии**: два клиента правят одну запись оффлайн, delete-vs-edit, гонка
  CommitManifest (параллельные горутины), обрыв сети посередине заливки, реиграние WAL после kill -9.
* **Совместимость**: golden-тесты на реальных сторах `pass` и `passage`; прогон вырезки
  из официального тест-сьюта pass поверх `binpass` с симлинком `pass → binpass`.
* **E2E CLI**: `testscript` (rogpeppe/go-internal) — сценарии как txt-файлы.
* **Docs**: godoc на каждый пакет (`doc.go`), `golangci-lint` с `revive.exported` + `godot`,
  README + `docs/` (архитектура, протокол, миграция, threat model), Swagger UI из `protoc-gen-openapiv2` на `/swagger/index.html`.

CI: lint → unit+race → coverage gate → integration → build matrix (3 ОС × 2 арх) →
`gosec` + `govulncheck` → goreleaser (подписанные артефакты, SBOM).

---

## 13. Дорожная карта

| Этап | Содержание | Результат |
|---|---|---|
| **M0** | Каркас, `pkg/secret`, `pkg/crypto/age`, `pkg/storage/fs`, CLI-ядро | Локальный pass-совместимый менеджер, `version` работает |
| **M1** | `pkg/otp`, типы `card`/`binary`/`text`, `migrate` с GPG | Все типы данных из ТЗ + OTP |
| **M2** | Манифест, объекты, version vectors, движок sync, WAL, remote `fs` | Синхронизация через общую папку, конфликт-резолвер |
| **M3** | `binpassd` по go-clean-template: entity/usecase/repo, gRPC-контроллер + gateway, PG, blobstore | Полное покрытие обязательной части ТЗ |
| **M4** | Remote `git`, remote `rclone` (S3/WebDAV/Drive/Yandex) | Три бэкенда за одним интерфейсом |
| **M5** | Агент, TUI, `Watch`, audit/HIBP, GC | Необязательные пункты ТЗ + удобство |
| **M6** | Покрытие ≥70%, интеграционные тесты, goreleaser, docs | Релиз |

Критический путь — M2: если модель манифеста и конфликтов заложена правильно, M3–M4
становятся тремя реализациями одного интерфейса, а не тремя разными проектами.

---

## 14. Открытые вопросы

1. **Один пользователь = одно хранилище?** Или нужны несколько сторов/маунтов, как в gopass
   (`binpass mounts add work ~/work-secrets`)? Влияет на схему БД и на модель авторизации.
2. **Шаринг между людьми** — только через age-recipients (сервер не в курсе), или сервер должен
   уметь групповой доступ? Второе сильно усложняет авторизацию и ломает «сервер ничего не знает».
3. **Восстановление доступа**: забыл мастер-фразу — данные потеряны навсегда. Нужны ли
   recovery-коды (Shamir по ключу) или это приемлемо?
4. **Ротация ключей**: `reencrypt` всего стора при отзыве устройства — какой ожидается объём
   хранилища (это O(n) перезаливка)?
5. **Максимальный размер бинарника** для квот и выбора стратегии чанкования.
6. **Требуется ли поддержка существующих gopass-сторов на GPG в постоянном режиме**, или GPG
   нужен только как одноразовый мост при миграции?

---

## 15. Зафиксированный стек

| Слой | Выбор |
|---|---|
| CLI | `spf13/cobra` + `spf13/pflag` |
| Конфиг | `spf13/viper` (YAML + ENV + флаги) + `go-playground/validator` |
| Основной транспорт | `grpc/grpc-go` + `protobuf`, кодогенерация через `buf` |
| REST-фасад | `grpc-ecosystem/grpc-gateway/v2` + `gin-gonic/gin` (health, metrics, swagger) |
| Swagger | `protoc-gen-openapiv2` → `/swagger` |
| HTTP-клиент | `go-resty/resty/v2` — резервный REST-транспорт клиента |
| БД | PostgreSQL + `jackc/pgx/v5`, миграции `golang-migrate` |
| Крипто | `filippo.io/age`, `x/crypto/argon2`, `crypto/ed25519` |
| Бэкенды remote | `go-git/go-git/v5`, `rclone/rclone` (точечные импорты backend'ов) |
| Логи | `log/slog` (text для CLI, json для сервера) |
| Тесты | `stretchr/testify`, `golang/mock`, `testcontainers-go`, `rogpeppe/go-internal/testscript` |
| TUI (опц.) | `charmbracelet/bubbletea` |
| Сборка | `goreleaser`, `Makefile`, `golangci-lint` |
