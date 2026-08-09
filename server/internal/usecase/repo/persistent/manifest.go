package persistent

import (
	"context"
	"errors"

	"github.com/71g3pf4c3/binpass/server/internal/entity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ManifestRepo is the PostgreSQL implementation of usecase.ManifestRepo.
type ManifestRepo struct {
	// pool is the pgx connection pool.
	pool *pgxpool.Pool
}

// NewManifestRepo builds a ManifestRepo.
func NewManifestRepo(pool *pgxpool.Pool) *ManifestRepo { return &ManifestRepo{pool: pool} }

// Latest returns the newest manifest for a user.
func (r *ManifestRepo) Latest(ctx context.Context, userID string) (entity.Manifest, error) {
	var m entity.Manifest
	err := r.pool.QueryRow(ctx,
		`SELECT user_id, generation, blob, signature, public_key, device_id, created_at
		 FROM manifests WHERE user_id = $1
		 ORDER BY generation DESC LIMIT 1`, userID).
		Scan(&m.UserID, &m.Generation, &m.Blob, &m.Signature, &m.PublicKey, &m.DeviceID, &m.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return entity.Manifest{}, entity.ErrNotFound
	}
	return m, err
}

// InsertIfNext inserts a manifest only when its generation is exactly one
// past the current latest. The primary key (user_id, generation) turns a
// concurrent commit into a unique violation, which maps to a CAS mismatch.
func (r *ManifestRepo) InsertIfNext(ctx context.Context, m entity.Manifest, expectGeneration uint64) error {
	tag, err := r.pool.Exec(ctx,
		`INSERT INTO manifests (user_id, generation, blob, signature, public_key, device_id, created_at)
		 SELECT $1, $2, $3, $4, $5, $6, $7
		 WHERE COALESCE((SELECT MAX(generation) FROM manifests WHERE user_id = $1), 0) = $8`,
		m.UserID, m.Generation, m.Blob, m.Signature, m.PublicKey, m.DeviceID, m.CreatedAt, expectGeneration)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
		return entity.ErrGenerationMismatch
	}
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return entity.ErrGenerationMismatch
	}
	return nil
}
