package repository

import (
	"context"
	"github.com/jackc/pgx/v5"
)

//go:generate mockgen -source=$GOFILE -destination=../mocks/mock_$GOFILE -package=mocks
//go:generate mockgen -destination=../mocks/mock_pgx.go -package=mocks github.com/jackc/pgx/v5 Tx
type Transactor interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}
