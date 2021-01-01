package services

import (
	"context"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
)

type dbContextKey int

const (
	ctxDbConnection dbContextKey = iota
)

type DatabaseParams struct {
	ConnMaxLifeTime    time.Duration
	DSN                string
	MaxOpenConnections int
	MaxIdleConnections int
}

func NewDatabaseParams(dsn string) *DatabaseParams {
	return &DatabaseParams{
		DSN:                dsn,
		ConnMaxLifeTime:    time.Minute * 3,
		MaxOpenConnections: 10,
		MaxIdleConnections: 10,
	}
}

func InitDatabase(ctx context.Context, params *DatabaseParams) (context.Context, error) {
	db, err := sqlx.Connect("mysql", params.DSN)
	if err != nil {
		return nil, err
	}
	db.SetConnMaxLifetime(params.ConnMaxLifeTime)
	db.SetMaxOpenConns(params.MaxOpenConnections)
	db.SetMaxIdleConns(params.MaxIdleConnections)
	return context.WithValue(ctx, ctxDbConnection, db), nil
}

func GetDb(ctx context.Context) *sqlx.DB {
	return ctx.Value(ctxDbConnection).(*sqlx.DB)
}
