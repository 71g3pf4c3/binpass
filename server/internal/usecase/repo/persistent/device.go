package persistent

import (
	"context"
	"errors"
	"time"

	"github.com/71g3pf4c3/binpass/server/internal/entity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DeviceRepo is the PostgreSQL implementation of usecase.DeviceRepo.
type DeviceRepo struct {
	// pool is the pgx connection pool.
	pool *pgxpool.Pool
}

// NewDeviceRepo builds a DeviceRepo.
func NewDeviceRepo(pool *pgxpool.Pool) *DeviceRepo { return &DeviceRepo{pool: pool} }

// Create inserts a new device.
func (r *DeviceRepo) Create(ctx context.Context, d entity.Device) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO devices (id, user_id, name, created_at, last_seen_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		d.ID, d.UserID, d.Name, d.CreatedAt, d.LastSeenAt)
	return err
}

// ByID returns a device by ID.
func (r *DeviceRepo) ByID(ctx context.Context, id string) (entity.Device, error) {
	var d entity.Device
	err := r.pool.QueryRow(ctx,
		`SELECT id, user_id, name, created_at, last_seen_at, revoked_at
		 FROM devices WHERE id = $1`, id).
		Scan(&d.ID, &d.UserID, &d.Name, &d.CreatedAt, &d.LastSeenAt, &d.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return entity.Device{}, entity.ErrNotFound
	}
	return d, err
}

// ListByUser returns all devices of a user, newest first.
func (r *DeviceRepo) ListByUser(ctx context.Context, userID string) ([]entity.Device, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, user_id, name, created_at, last_seen_at, revoked_at
		 FROM devices WHERE user_id = $1 ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []entity.Device
	for rows.Next() {
		var d entity.Device
		if err := rows.Scan(&d.ID, &d.UserID, &d.Name, &d.CreatedAt, &d.LastSeenAt, &d.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// Revoke marks a device revoked.
func (r *DeviceRepo) Revoke(ctx context.Context, userID, deviceID string, at time.Time) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE devices SET revoked_at = $1 WHERE id = $2 AND user_id = $3`,
		at, deviceID, userID)
	return err
}

// Touch updates the device's last-seen timestamp.
func (r *DeviceRepo) Touch(ctx context.Context, deviceID string, at time.Time) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE devices SET last_seen_at = $1 WHERE id = $2`, at, deviceID)
	return err
}
