package persistent

import (
	"context"
	"errors"

	"github.com/71g3pf4c3/binpass/server/internal/entity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ObjectRepo is the PostgreSQL implementation of usecase.ObjectRepo.
type ObjectRepo struct {
	// pool is the pgx connection pool.
	pool *pgxpool.Pool
}

// NewObjectRepo builds an ObjectRepo.
func NewObjectRepo(pool *pgxpool.Pool) *ObjectRepo { return &ObjectRepo{pool: pool} }

// Exists reports which of the given OIDs exist for the user.
func (r *ObjectRepo) Exists(ctx context.Context, userID string, oids []string) (map[string]bool, error) {
	present := make(map[string]bool, len(oids))
	for _, oid := range oids {
		present[oid] = false
	}
	if len(oids) == 0 {
		return present, nil
	}
	rows, err := r.pool.Query(ctx,
		`SELECT oid FROM objects WHERE user_id = $1 AND oid = ANY($2)`, userID, oids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var oid string
		if err := rows.Scan(&oid); err != nil {
			return nil, err
		}
		present[oid] = true
	}
	return present, rows.Err()
}

// Upsert records object metadata, ignoring duplicates.
func (r *ObjectRepo) Upsert(ctx context.Context, o entity.Object) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO objects (user_id, oid, size, storage_ref, created_at)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (user_id, oid) DO NOTHING`,
		o.UserID, o.OID, o.Size, o.StorageRef, o.CreatedAt)
	return err
}

// Get returns object metadata.
func (r *ObjectRepo) Get(ctx context.Context, userID, oid string) (entity.Object, error) {
	var o entity.Object
	err := r.pool.QueryRow(ctx,
		`SELECT user_id, oid, size, storage_ref, created_at
		 FROM objects WHERE user_id = $1 AND oid = $2`, userID, oid).
		Scan(&o.UserID, &o.OID, &o.Size, &o.StorageRef, &o.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return entity.Object{}, entity.ErrNotFound
	}
	return o, err
}
