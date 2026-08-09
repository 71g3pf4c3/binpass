// Package postgres wraps a pgx connection pool with sane defaults for
// binpassd.
package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Postgres holds a configured pgx pool.
type Postgres struct {
	// Pool is the underlying pgx connection pool.
	Pool *pgxpool.Pool
}

// New connects to PostgreSQL at url with the given max pool size, retrying a
// few times to tolerate a slow-starting database (e.g. in docker-compose).
func New(ctx context.Context, url string, maxConns int32) (*Postgres, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("postgres: parse config: %w", err)
	}
	if maxConns > 0 {
		cfg.MaxConns = maxConns
	}

	var pool *pgxpool.Pool
	var lastErr error
	for attempt := 0; attempt < 10; attempt++ {
		pool, lastErr = pgxpool.NewWithConfig(ctx, cfg)
		if lastErr == nil {
			if lastErr = pool.Ping(ctx); lastErr == nil {
				return &Postgres{Pool: pool}, nil
			}
			pool.Close()
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return nil, fmt.Errorf("postgres: connect: %w", lastErr)
}

// Close releases the pool.
func (p *Postgres) Close() {
	if p.Pool != nil {
		p.Pool.Close()
	}
}
