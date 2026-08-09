package persistent

import (
	"context"
	"errors"
	"time"

	"github.com/71g3pf4c3/binpass/server/internal/entity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TokenRepo is the PostgreSQL implementation of usecase.TokenRepo.
type TokenRepo struct {
	// pool is the pgx connection pool.
	pool *pgxpool.Pool
}

// NewTokenRepo builds a TokenRepo.
func NewTokenRepo(pool *pgxpool.Pool) *TokenRepo { return &TokenRepo{pool: pool} }

// Create stores a new refresh token.
func (r *TokenRepo) Create(ctx context.Context, t entity.RefreshToken) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO refresh_tokens (id, device_id, user_id, token_hash, expires_at, revoked)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		t.ID, t.DeviceID, t.UserID, t.TokenHash, t.ExpiresAt, t.Revoked)
	return err
}

// ByHash returns a token by its hash.
func (r *TokenRepo) ByHash(ctx context.Context, hash string) (entity.RefreshToken, error) {
	var t entity.RefreshToken
	err := r.pool.QueryRow(ctx,
		`SELECT id, device_id, user_id, token_hash, expires_at, used_at, revoked
		 FROM refresh_tokens WHERE token_hash = $1`, hash).
		Scan(&t.ID, &t.DeviceID, &t.UserID, &t.TokenHash, &t.ExpiresAt, &t.UsedAt, &t.Revoked)
	if errors.Is(err, pgx.ErrNoRows) {
		return entity.RefreshToken{}, entity.ErrNotFound
	}
	return t, err
}

// MarkUsed records rotation of a token.
func (r *TokenRepo) MarkUsed(ctx context.Context, id string, at time.Time) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE refresh_tokens SET used_at = $1 WHERE id = $2`, at, id)
	return err
}

// Revoke revokes a single token.
func (r *TokenRepo) Revoke(ctx context.Context, id string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE refresh_tokens SET revoked = TRUE WHERE id = $1`, id)
	return err
}

// RevokeByDevice revokes all tokens of a device.
func (r *TokenRepo) RevokeByDevice(ctx context.Context, deviceID string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE refresh_tokens SET revoked = TRUE WHERE device_id = $1`, deviceID)
	return err
}
