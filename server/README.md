# binpassd — binpass synchronisation server

`binpassd` is the server half of binpass. It implements the required server
business logic: **registration, authentication, authorisation, private-data
storage, multi-device synchronisation for a single owner, and on-demand data
delivery**. The server is end-to-end encrypted: it only ever handles
ciphertext and hashes — never plaintext or encryption keys.

## Architecture

Clean Architecture (`evrone/go-clean-template` layout). Dependencies point
inward; the `usecase` layer knows nothing about gRPC, HTTP, or PostgreSQL.

```
cmd/binpassd/            main → config → app.Run(cfg)
config/                  viper config (YAML + ENV), secrets from ENV only
api/proto/v1/            *.proto — the single source of truth for the contract
gen/                     buf-generated: pb.go, gRPC, gateway, openapiv2
internal/
  entity/                pure domain types, zero deps
  usecase/               AuthUseCase, VaultUseCase; contracts.go owns the ports
    repo/persistent/     PostgreSQL (pgx) repositories
    repo/blob/           fs BlobStore
    repo/eventbus/       in-process change-event fan-out (Watch)
  controller/
    grpc/v1/             Auth + Vault controllers, auth interceptors
    http/v1/             grpc-gateway REST, health, metrics, swagger
  app/                   DI assembly, embedded migrations, graceful shutdown
migrations/              golang-migrate SQL
client/remote/           client-side Remote interface + gRPC implementation
integration-test/        testcontainers full-cycle test
pkg/                     argon2, jwt, postgres, logger, httpserver, grpcserver
```

## Transport

- **gRPC over TLS 1.3** is the primary (binary) transport (port 8081).
- **grpc-gateway** exposes a REST facade and generates OpenAPI/Swagger
  (port 8080): `/api/v1/...`, `/healthz`, `/readyz`, `/metrics`,
  `/swagger/`.
- Streaming object upload/download is gRPC-only (client streaming cannot map
  cleanly to REST); all unary operations are available over both.

### Error mapping

| Domain                       | gRPC                  | HTTP |
|------------------------------|-----------------------|------|
| Manifest CAS race            | `FAILED_PRECONDITION` | 412  |
| Not found                    | `NOT_FOUND`           | 404  |
| Bad/expired token            | `UNAUTHENTICATED`     | 401  |
| Foreign resource             | `PERMISSION_DENIED`   | 403  |
| Login taken                  | `ALREADY_EXISTS`      | 409  |
| Quota / object too large     | `RESOURCE_EXHAUSTED`  | 429  |

## Security model

- Clients derive an `auth_secret` from their master phrase (HKDF). The server
  stores only `Argon2id(auth_secret)` and a per-user salt — never the phrase.
- Access tokens are Ed25519 JWTs (15 min). Refresh tokens are opaque, hashed
  at rest, bound to a device, rotated on every use; reuse of a rotated token
  revokes the whole device chain.
- Objects are content-addressed ciphertext; manifests are committed under
  compare-and-swap on a monotonic generation for transactional multi-file ops.

## Running locally

```sh
docker compose up --build         # PostgreSQL + binpassd
curl localhost:8080/healthz
open http://localhost:8080/swagger/
```

Or against your own PostgreSQL:

```sh
export BINPASSD_PG_URL="postgres://binpass:binpass@localhost:5432/binpass?sslmode=disable"
export BINPASSD_JWT_PRIVATE_KEY="$(head -c 32 /dev/urandom | base64)"
make build && ./bin/binpassd --config config/config.yaml
```

## Development

```sh
make gen      # regenerate proto/gRPC/gateway/swagger (buf)
make test     # unit tests
make cover    # coverage summary
go test ./integration-test/...   # full-cycle test (requires Docker)
```

### Configuration

Precedence: **flags > ENV > YAML file > code defaults**. Secrets
(`pg.url`, `auth.jwt_private_key`) come **only** from ENV:
`BINPASSD_PG_URL`, `BINPASSD_JWT_PRIVATE_KEY`. All other keys map as
`BINPASSD_<SECTION>_<KEY>` (e.g. `BINPASSD_HTTP_PORT`).

## Testing & coverage

Business logic is unit-tested above the 70% bar (usecase 74.6%, argon2 81.5%,
jwt 84.4%, eventbus 100%, blob 70.2%). The persistent repositories and the
full transport stack are covered by the testcontainers integration test.
