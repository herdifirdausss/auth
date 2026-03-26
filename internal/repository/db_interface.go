package repository

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// DB defines the interface for database operations, compatible with pgxpool.Pool and pgx.Tx
type DB interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

//go:generate mockgen -source=$GOFILE -destination=../mocks/mock_$GOFILE -package=mocks
// Pool defines the interface for a connection pool
type Pool interface {
	DB
	Begin(ctx context.Context) (pgx.Tx, error)
	Close()
	Ping(ctx context.Context) error
}
