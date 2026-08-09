// Package persistent implements the usecase repository ports on top of
// PostgreSQL using pgx.
package persistent

import (
	"context"
	"errors"

	"github.com/71g3pf4c3/binpass/server/internal/entity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// uniqueViolation is the PostgreSQL SQLSTATE for a unique-constraint breach.
const uniqueViolation = "23505"

// UserRepo is the PostgreSQL implementation of usecase.UserRepo.
type UserRepo struct {
	// pool is the pgx connection pool.
	pool *pgxpool.Pool
}

// NewUserRepo builds a UserRepo.
func NewUserRepo(pool *pgxpool.Pool) *UserRepo { return &UserRepo{pool: pool} }

// Create inserts a new user, mapping a unique violation to ErrLoginTaken.
func (r *UserRepo) Create(ctx context.Context, u entity.User) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO users (id, login, auth_hash, user_salt, created_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		u.ID, u.Login, u.AuthHash, u.UserSalt, u.CreatedAt)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
		return entity.ErrLoginTaken
	}
	return err
}

// ByLogin returns the user with the given login.
func (r *UserRepo) ByLogin(ctx context.Context, login string) (entity.User, error) {
	return r.scanUser(ctx,
		`SELECT id, login, auth_hash, user_salt, created_at FROM users WHERE login = $1`, login)
}

// ByID returns the user with the given ID.
func (r *UserRepo) ByID(ctx context.Context, id string) (entity.User, error) {
	return r.scanUser(ctx,
		`SELECT id, login, auth_hash, user_salt, created_at FROM users WHERE id = $1`, id)
}

// scanUser runs a single-row user query and maps no-rows to ErrNotFound.
func (r *UserRepo) scanUser(ctx context.Context, query string, arg any) (entity.User, error) {
	var u entity.User
	err := r.pool.QueryRow(ctx, query, arg).
		Scan(&u.ID, &u.Login, &u.AuthHash, &u.UserSalt, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return entity.User{}, entity.ErrNotFound
	}
	return u, err
}
