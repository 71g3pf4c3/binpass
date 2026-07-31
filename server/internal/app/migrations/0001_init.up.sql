-- Initial binpassd schema: users, devices, refresh tokens, manifests,
-- objects, and an audit log. The server stores only ciphertext and hashes.

CREATE TABLE IF NOT EXISTS users (
    id         UUID PRIMARY KEY,
    login      TEXT NOT NULL UNIQUE,
    auth_hash  TEXT NOT NULL,
    user_salt  BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS devices (
    id           UUID PRIMARY KEY,
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id         UUID PRIMARY KEY,
    device_id  UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    revoked    BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_refresh_device ON refresh_tokens(device_id);

CREATE TABLE IF NOT EXISTS manifests (
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    generation BIGINT NOT NULL,
    blob       BYTEA NOT NULL,
    signature  BYTEA NOT NULL,
    public_key BYTEA NOT NULL,
    device_id  UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, generation)
);

CREATE TABLE IF NOT EXISTS objects (
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    oid         TEXT NOT NULL,
    size        BIGINT NOT NULL,
    storage_ref TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, oid)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id        BIGSERIAL PRIMARY KEY,
    user_id   UUID,
    device_id UUID,
    action    TEXT NOT NULL,
    ip        TEXT,
    at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
