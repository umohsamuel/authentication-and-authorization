package user

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/umohsamuel/authentication-authorization/internal/adapters/database/sqlc"
	"github.com/umohsamuel/authentication-authorization/pkg/env"
	"github.com/umohsamuel/authentication-authorization/pkg/util"
)

type Handler struct {
	environmentVariables env.EnvironmentVariables
	queries              sqlc.Queries
}

func NewUserHandler(environmentVariables env.EnvironmentVariables, queries sqlc.Queries) *Handler {
	return &Handler{
		environmentVariables: environmentVariables,
		queries:              queries,
	}
}

type SignUpRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (h *Handler) SignUp(c *gin.Context) {
	var signUpReq SignUpRequest

	if err := c.ShouldBindJSON(&signUpReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid request params",
		})
		return
	}

	password_hash, err := util.HashPassword(signUpReq.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "",
		})
		return
	}

	user, err := h.queries.AddUser(c, sqlc.AddUserParams{
		Email:        signUpReq.Email,
		PasswordHash: password_hash,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "failed to create user",
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "user created successfully",
		"data":    user,
	})
}
