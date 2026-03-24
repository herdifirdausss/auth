package repository

import (
	"context"
	"github.com/jackc/pgx/v5"
)

//go:generate mockgen -source=$GOFILE -destination=mock_$GOFILE -package=repository
type Transactor interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}
