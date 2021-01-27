/*
 Copyright 2020, 2021 Jan Dittberner


 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/

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
