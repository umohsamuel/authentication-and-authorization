package main

import (
	"github.com/umohsamuel/authentication-authorization/cmd/api"
	"github.com/umohsamuel/authentication-authorization/internal/adapters/database"
	"github.com/umohsamuel/authentication-authorization/internal/adapters/database/sqlc"
	"github.com/umohsamuel/authentication-authorization/pkg/env"
)

var (
	environmentVariables = env.LoadEnvironmentVariables()
)

// func init() {
// 	env.LoadEnvironmentVariables()
// }

func main() {

	db := database.NewPool()

	queries := sqlc.New(db)

	api.API(environmentVariables, queries)

}
