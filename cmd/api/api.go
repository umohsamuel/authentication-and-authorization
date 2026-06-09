package api

import (
	"net/http"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/umohsamuel/authentication-authorization/internal/adapters/database/sqlc"
	"github.com/umohsamuel/authentication-authorization/internal/ports/http/handlers/user"
	"github.com/umohsamuel/authentication-authorization/pkg/env"
)

type Server struct {
	Engine  *gin.Engine
	Env     *env.EnvironmentVariables
	Queries *sqlc.Queries
}

func API(environmentVariables *env.EnvironmentVariables, queries *sqlc.Queries) *Server {

	s := &Server{
		Engine:  gin.Default(),
		Env:     environmentVariables,
		Queries: queries,
	}

	config := cors.DefaultConfig()
	config.AllowAllOrigins = true
	config.AllowMethods = []string{"POST", "GET", "PUT", "OPTIONS"}
	config.AllowHeaders = []string{"Origin", "Content-Type", "Authorization", "Accept", "User-Agent", "Cache-Control", "Pragma"}
	config.ExposeHeaders = []string{"Content-Length"}
	config.AllowCredentials = true
	config.MaxAge = 12 * time.Hour

	s.Engine.Use(cors.New(config))

	s.Engine.Static("/downloads", "tmp")

	s.Health()
	s.User()

	s.Engine.Run()

	return s
}

func (s *Server) Health() {
	s.Engine.GET("/health", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{
			"message": "Server Up!",
		})
	})
}

func (s *Server) User() {
	userHandler := user.NewUserHandler(*s.Env, *s.Queries)

	s.Engine.POST("/user", userHandler.SignUp)
}
