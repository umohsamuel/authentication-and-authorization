package user

import (
	"net/http"
	"time"

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
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "user created successfully",
		"data":    user,
	})

}
func (h *Handler) SignIn(c *gin.Context) {
	var signUpReq SignUpRequest

	if err := c.ShouldBindJSON(&signUpReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid request params",
		})
		return
	}

	user, err := h.queries.GetUser(c, signUpReq.Email)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "user not found",
		})
		return
	}

	if password_match := util.CheckPasswordHash(signUpReq.Password, user.PasswordHash); password_match != true {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid details",
		})
		return
	}

	token, err := util.GenerateAccessToken(*user, []byte(h.environmentVariables.Authentication.JWT_SECRET), 30*time.Minute)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "failed to generate access token",
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "login successful",
		"data":    user,
		"token":   token,
	})
}
