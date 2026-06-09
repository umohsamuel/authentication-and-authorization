package user

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
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

type SignInRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (h *Handler) SignIn(c *gin.Context) {
	var signInReq SignInRequest

	if err := c.ShouldBindJSON(&signInReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid request params",
		})
		return
	}

	user, err := h.queries.GetUser(c, signInReq.Email)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "user not found",
		})
		return
	}

	if password_match := util.CheckPasswordHash(signInReq.Password, user.PasswordHash); password_match != true {
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

	refreshToken, err := h.queries.CreateRefreshToken(c, sqlc.CreateRefreshTokenParams{
		UserID:    user.ID,
		Token:     uuid.New().String(),
		ExpiresAt: time.Now().UTC().Add(7 * 24 * time.Hour),
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "failed to generate refresh token",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "login successful",
		"data":    user,
		"jwt": gin.H{
			"token":         token,
			"refresh_token": refreshToken.Token,
		},
	})
}

type RefreshAccessTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (h *Handler) RefreshAccessToken(c *gin.Context) {
	var refreshAccessReq RefreshAccessTokenRequest

	if err := c.ShouldBind(&refreshAccessReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid request params",
		})
		return
	}

	rt, err := h.queries.GetRefreshToken(c, refreshAccessReq.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "invalid refresh token",
		})
		return
	}

	if rt.Revoked {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "invalid refresh token",
		})
		return
	}

	if time.Now().UTC().After(rt.ExpiresAt) {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "expired refresh token",
		})
		return
	}

	user, err := h.queries.GetUserByID(c, rt.UserID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "invalid refresh token",
		})
		return
	}

	accessToken, err := util.GenerateAccessToken(*user, []byte(h.environmentVariables.Authentication.JWT_SECRET), 30*time.Minute)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "failed to generate access token",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "success",
		"jwt": gin.H{
			"token": accessToken,
		},
	})
}

type RevokeRefreshAccessTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (h *Handler) RevokeRefreshAccessToken(c *gin.Context) {
	var refreshAccessReq RefreshAccessTokenRequest

	if err := c.ShouldBind(&refreshAccessReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid request params",
		})
		return
	}

	err := h.queries.RevokeRefreshToken(c, refreshAccessReq.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "failed to revoke refresh token",
		})
		return
	}

	c.JSON(http.StatusNoContent, gin.H{})
}
