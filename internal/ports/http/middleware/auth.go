package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/umohsamuel/authentication-authorization/pkg/env"
	"github.com/umohsamuel/authentication-authorization/pkg/util"
)

func AuthMiddleware(environmentVariables env.EnvironmentVariables) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization header required",
			})
			c.Abort()
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid authorization format",
			})
			c.Abort()
			return
		}

		tokenString := parts[1]

		claims, err := util.ValidateToken(tokenString, []byte(environmentVariables.Authentication.JWT_SECRET))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid or expired token",
			})
			c.Abort()
			return
		}

		userIDStr, ok := claims["sub"].(string)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid token",
			})
			c.Abort()
			return
		}

		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid token",
			})
			c.Abort()
			return
		}

		rawRoles, ok := claims["roles"].([]interface{})
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid token",
			})
			c.Abort()
			return
		}

		roles := make([]string, len(rawRoles))
		for i, r := range rawRoles {
			roles[i] = r.(string)
		}

		c.Set("userID", userID)
		c.Set("roles", roles)

		c.Next()
	}
}

func RoleMiddleware(requiredRoles []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		rolesValue, exists := c.Get("roles")

		if !exists {
			c.AbortWithStatus(http.StatusUnauthorized)

			return
		}

		roles := rolesValue.([]string)

		hasRole := false

		for _, r := range roles {
			for _, rr := range requiredRoles {
				if r == rr {
					hasRole = true
				}
			}
		}

		if !hasRole {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Forbidden",
			})
			c.Abort()
			return
		}

		c.Next()

	}
}
