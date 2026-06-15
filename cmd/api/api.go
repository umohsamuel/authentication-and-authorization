package api

import (
	"net/http"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/umohsamuel/authentication-authorization/internal/adapters/database/sqlc"
	"github.com/umohsamuel/authentication-authorization/internal/ports/http/handlers/user"
	"github.com/umohsamuel/authentication-authorization/internal/ports/http/middleware"
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

	auth := s.Engine.Group("/auth")
	s.Auth(auth)

	v1 := s.Engine.Group("/api/v1")
	{

		protected := v1.Group("")
		protected.Use(middleware.AuthMiddleware(*s.Env))
		{
			s.Health(protected)
			s.OnlyMinLevelAdmin(protected)
		}

	}

	s.Engine.Run()

	return s
}

func (s *Server) Health(rg *gin.RouterGroup) {
	rg.GET("/health", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{
			"message": "Server Up!",
		})
	})
}

func (s *Server) OnlyMinLevelAdmin(rg *gin.RouterGroup) {
	g := rg.Group("/admin")

	requiredRoles := []string{"super-admin", "admin"}

	g.Use(middleware.RoleMiddleware(requiredRoles))

	g.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"success": "you have successfully implemented RBAC",
		})
	})

}

func (s *Server) Auth(rg *gin.RouterGroup) {
	userHandler := user.NewUserHandler(*s.Env, *s.Queries)

	rg.POST("/signup", userHandler.SignUp)
	rg.POST("/signin", userHandler.SignIn)
	rg.POST("/refresh", userHandler.RefreshAccessToken)

	// admin in case of revoking access token
	rg.POST("/revoke-refresh", userHandler.RevokeRefreshAccessToken)
}
