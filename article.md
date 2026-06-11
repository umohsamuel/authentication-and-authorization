# Build a Secure Authentication System in Golang with Gin, JWT, and Postgres

Securing user data is a very important part of building any application. At the core of this security are two foundational concepts: authentication and authorization.

While these terms are often used interchangeably, they represent fundamentally different functions.

## What are Authentication and Authorization?

Simply put, authentication is the process of verifying who a user is, while authorization is the process of verifying what they have access to.

Comparing these processes to a real-world example, when you go to write an external examination (say JAMB), a student presents their exam slip and ID card (authentication). Then once inside, they can only sit for the subjects they registered for and not any random exam they choose (authorization).

This simple process is the foundation for web applications; it ensures that the users are who they claim to be and also ensures they can only access what they are allowed to access.

While both are equally important, this article will focus specifically on the first step: how to build a secure authentication system in Golang using JSON Web Tokens and PostgreSQL.

## Prerequisites

What would you need to follow along?

1. Golang installed on your laptop or computer.
2. Basic familiarity with SQL and Go.

## Understanding JSON Web Tokens (JWT)

A JSON Web Token (JWT) is a compact, self-contained way to transmit information between two parties as a JSON object securely. It's designed to ensure data integrity and authenticity without the need for server-side session management. It is secure because the token's data is digitally signed using a shared secret (HMAC) or public/private key pair (RSA).

JWTs are essential in an authentication system because their statelessness eliminates the need for repeated database queries, thereby reducing server load and improving response times.

### JWT Structure

A JWT consists of three parts encoded in Base64URL format and separated by dots:

```text
Header.Payload.Signature
```

For example:

```text
eyJhbGciOiJIUzI1NiJ9.eyJlbWFpbCI6InVtb2hzZy5hbHRAZ2LTMzMzlhZDIzNzNjZSJ9.RVQk03jen6HzfHnjXkTiD612gMDrNtFsExWKElWElDg
```

1. The header identifies the algorithm used for signing.
2. The payload contains claims about the user like ID, roles, and expiration time.
3. The signature verifies the token hasn't been tampered with.

### The Role of JWT in Our System

When a user interacts with our system:

1. When the user successfully authenticates, our Go service:
   1. Validates the user credentials against PostgreSQL data.
   2. Creates a JWT with the appropriate claims and expiration.
   3. Signs the token with a secret key.
2. The client:
   1. Stores the JWT (mostly in localStorage or Cookie).
   2. Includes the token in the Authorization header for subsequent requests.
3. Our middleware:
   1. Extracts the JWT from the request header.
   2. Validates the signature using our secret key.
   3. Checks that the token hasn't expired.
   4. Extracts the user identity from the claims.
   5. Adds the user ID to the request context.
4. Since the token contains all the necessary user information, our server can authenticate requests without maintaining session state or making additional database queries.

The security of the JWT system depends on keeping the signing key secret and using short-lived access tokens. If a token is compromised, it's only valid for a limited time, reducing the risk of unauthorized access.

## Project Setup and Database Migrations

Let's initialize a new Go application and install the necessary dependencies:

```bash
mkdir authentication-authorization
cd authentication-authorization
go mod init github.com/you/authentication-authorization
```

Now let's install the essential packages:

```bash
go get github.com/gin-gonic/gin # HTTP web framework and router
go get github.com/gin-contrib/cors # Cross-Origin Resource Sharing (CORS) middleware
go get github.com/jackc/pgx/v5 # PostgreSQL driver
go get github.com/jackc/pgx/v5/pgconn # PostgreSQL connection
go get github.com/jackc/pgx/v5/pgxpool # Connection pooling
go get github.com/golang-jwt/jwt/v5 # JWT library
go get golang.org/x/crypto/bcrypt # Password hashing
go get github.com/google/uuid # UUID generation
go get github.com/joho/godotenv # Load environment variables
```

Next, let's install Goose for our database migrations:

```bash
go install github.com/pressly/goose/v3/cmd/goose@latest
```

Next, let's make a migrations folder:

```bash
mkdir migrations
```

Now, let's create our very first migration for this project.

Create a `.env` file and configure it with your PostgreSQL database credentials (replace `GOOSE_DBSTRING` with your actual database connection url):

```bash
export GOOSE_DRIVER=postgres
export GOOSE_DBSTRING=postgres://admin:admin@localhost:5432/admin_db
export GOOSE_MIGRATION_DIR=./migrations
```

Open your terminal and run:

```bash
goose create create_user_and_refresh_token_table sql
```

Paste this into the generated migration file:

```sql
-- migrations/..._create_user_and_refresh_token_table.sql

-- +goose Up
CREATE TABLE users (
 id uuid PRIMARY KEY DEFAULT uuidv7(),
 email VARCHAR(255) UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
-- refresh token table
CREATE TABLE refresh_tokens (
 id uuid PRIMARY KEY DEFAULT uuidv7(),
 user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 token VARCHAR(255) UNIQUE NOT NULL,
 expires_at TIMESTAMPTZ NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
 revoked BOOLEAN NOT NULL DEFAULT FALSE
);
-- index for fast lookups
CREATE INDEX idx_refresh_tokens_token ON refresh_tokens(token);
-- +goose Down
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS refresh_tokens;
DROP INDEX IF EXISTS idx_refresh_tokens_token;
```

Now we can apply the migration in our terminal:

```bash
goose up
```

And if you check your PostgreSQL database, the appropriate tables and fields have been created.

## Loading Environment Variables

Our application requires configuration such as the Port, database URL and JWT secret. Let's create an `env` package to handle loading these variables using `godotenv`:

```go
// pkg/env/env.go
package env

import (
	"log"
	"os"
	"strconv"
   "regexp"

	"github.com/joho/godotenv"
	"github.com/umohsamuel/authentication-authorization/pkg/util"
)

type AuthenticationEV struct {
	JWT_SECRET string
}

type DatabaseEV struct {
	PG_PORT      int
	DATABASE_URL string
}

type EnvironmentVariables struct {
	Port                  string
	ProductionEnvironment bool
	ClientDomain          string
	ProjectName           string
	Authentication        AuthenticationEV
	Database              DatabaseEV
}

func loadEnv() {
	rootPath := GetRootPath()
	err := godotenv.Load(rootPath + `/.env`)

	if err != nil {
		log.Println("Warning: .env file not found, using environment variables")
	}
}

func LoadEnvironmentVariables() *EnvironmentVariables {
	loadEnv()

	return &EnvironmentVariables{
		Port:                  getEnv("PORT", ":5000"),
		ProductionEnvironment: getEnvAsBool("PRODUCTION_ENVIRONMENT", false),
		ClientDomain:          getEnv("CLIENT_DOMAIN", "localhost"),
		ProjectName:           getEnv("PROJECT_NAME", "eba"),
		Authentication: AuthenticationEV{
			JWT_SECRET: getEnvOrError("JWT_SECRET"),
		},
		Database: DatabaseEV{
			PG_PORT:      getEnvAsInt("PG_PORT", 5433),
			DATABASE_URL: getEnvOrError("DATABASE_URL"),
		},
	}
}

func getEnvOrError(key string) string {
	value, exists := os.LookupEnv(key)
	if exists {
		return value
	}
	panic("Environment variable " + key + " not set")
}

func getEnv(key string, fallback string) string {
	value, exists := os.LookupEnv(key)
	if exists {
		return value
	}
	return fallback
}

func getEnvAsInt(key string, fallback int) int {
	value, exist := os.LookupEnv(key)
	if exist {
		valueInt, err := strconv.Atoi(value)
		if err != nil {
			log.Panicf("Environment variable \"%v\" not set properly", key)
		}
		return valueInt
	}
	return fallback
}

func getEnvAsBool(key string, fallback bool) bool {
	value, exist := os.LookupEnv(key)
	if exist {
		valueBool, err := strconv.ParseBool(value)
		if err != nil {
			log.Panicf("Environment variable \"%v\" not set properly", key)
		}
		return valueBool
	}
	return fallback
}

func GetRootPath() string {
	projectDirName := os.Getenv("PROJECT_DIR_NAME")
	projectName := regexp.MustCompile(`^(.*` + projectDirName + `)`)
	currentWorkDirectory, _ := os.Getwd()
	return string(projectName.Find([]byte(currentWorkDirectory)))
}
```

Make sure to add the relevant environment variables to your `.env` file:

```bash
JWT_SECRET=your-super-secret-jwt-key
DATABASE_URL=postgres://admin:admin@localhost:5432/admin_db
```

## Database Connection Setup

Let's start with a connection to our PostgreSQL Database:

```go
// internal/adapters/database/connection.go
package database

import (
	"context"
	"database/sql"
	"log"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
)


func NewPool() *sql.DB {
	pool, err := pgxpool.New(context.Background(), os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatalf("unable to create pg pool: %v", err)
	}

	db := stdlib.OpenDBFromPool(pool)

	db.SetMaxIdleConns(5)
	db.SetMaxOpenConns(25)
	db.SetConnMaxIdleTime(1 * time.Second)
	db.SetConnMaxLifetime(30 * time.Second)

	if err := db.PingContext(context.Background()); err != nil {
		log.Fatalf("unable to reach database: %v", err)
	}

	log.Println("database created & is reachable")

	return db
}
```

This simple function connects to our PostgreSQL database, creates a connection pool, and pings the database to verify the connection.

## Password Hashing

Now we will create functions that will hash passwords safely during registration and verify them during login:

```go
// pkg/util/password.go

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
```

We use Bcrypt for password hashing because:

1. It is slow by design, making it impractical for brute-force attacks.
2. It is adaptive because it has an adjustable cost factor. This makes computing the hash deliberately computationally expensive, so we can increase security as hardware gets faster.
3. It automatically salts passwords. This guarantees that even if two users have the exact same password, their stored hashes will look completely different.

When a user signs up, we'll hash their password before storing it. When they log in, we'll compare their provided password against the stored hash.

## Database Models and Queries

For our database interactions, we will use `sqlc`, a powerful tool that generates fully type-safe Go code directly from SQL queries.

Normally, you would configure `sqlc` and run its CLI to generate these files for you. However, to keep this tutorial focused strictly on the authentication logic, we'll just create the necessary files manually.

First, let's add the foundational `db.go` file that `sqlc` uses to define the `Queries` struct and the database execution interface:

```go
// internal/adapters/database/sqlc/db.go
package sqlc

import (
	"context"
	"database/sql"
)

type DBTX interface {
	ExecContext(context.Context, string, ...interface{}) (sql.Result, error)
	PrepareContext(context.Context, string) (*sql.Stmt, error)
	QueryContext(context.Context, string, ...interface{}) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...interface{}) *sql.Row
}

func New(db DBTX) *Queries {
	return &Queries{db: db}
}

type Queries struct {
	db DBTX
}

func (q *Queries) WithTx(tx *sql.Tx) *Queries {
	return &Queries{
		db: tx,
	}
}
```

Now let's create a user model and adapter to interact with:

```go
// internal/adapters/database/sqlc/user.go
package sqlc

import (
	"context"

	"github.com/google/uuid"
)

type User struct {
	ID           uuid.UUID    `json:"id"`
	Email        string       `json:"email"`
	PasswordHash string       `json:"password_hash"`
	CreatedAt    sql.NullTime `json:"created_at"`
}


const addUser = `-- name: AddUser :one
INSERT INTO users (email, password_hash)
VALUES ($1, $2)
RETURNING id, email, password_hash, created_at
`

type AddUserParams struct {
	Email        string `json:"email"`
	PasswordHash string `json:"password_hash"`
}

func (q *Queries) AddUser(ctx context.Context, arg AddUserParams) (*User, error) {
	row := q.db.QueryRowContext(ctx, addUser, arg.Email, arg.PasswordHash)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Email,
		&i.PasswordHash,
		&i.CreatedAt,
	)
	return &i, err
}

const getUser = `-- name: GetUser :one
SELECT id, email, password_hash, created_at
FROM users
WHERE email = $1
`

func (q *Queries) GetUser(ctx context.Context, email string) (*User, error) {
	row := q.db.QueryRowContext(ctx, getUser, email)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Email,
		&i.PasswordHash,
		&i.CreatedAt,
	)
	return &i, err
}

const getUserByID = `-- name: GetUserByID :one
SELECT id, email, password_hash, created_at
FROM users
WHERE id = $1
`

func (q *Queries) GetUserByID(ctx context.Context, id uuid.UUID) (*User, error) {
	row := q.db.QueryRowContext(ctx, getUserByID, id)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Email,
		&i.PasswordHash,
		&i.CreatedAt,
	)
	return &i, err
}

const getUsers = `-- name: GetUsers :many
SELECT id, email, password_hash, created_at
FROM users
`

func (q *Queries) GetUsers(ctx context.Context) ([]*User, error) {
	rows, err := q.db.QueryContext(ctx, getUsers)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []*User
	for rows.Next() {
		var i User
		if err := rows.Scan(
			&i.ID,
			&i.Email,
			&i.PasswordHash,
			&i.CreatedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, &i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

```

This adapter provides methods to interact with a user/users. We'll need them for our authentication logic. The `User` struct represents the structure of the user data stored in the database.

## JWT Generation and Validation

```go
// pkg/util/auth.go

func GenerateAccessToken(user sqlc.User, jwtSecret []byte, accessTokenTTL time.Duration) (string, error) {
	expirationTime := time.Now().UTC().Add(accessTokenTTL)

	claims := jwt.MapClaims{
		"sub":   user.ID.String(),
		"email": user.Email,
		"exp":   expirationTime.Unix(),
		"iat":   time.Now().UTC().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func ValidateToken(tokenString string, jwtSecret []byte) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("invalid token")
		}
		return jwtSecret, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, errors.New("token expired")
		}
		return nil, errors.New("invalid token")
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("invalid token")
}

```

Short-lived access tokens are more secure, but they require users to log in frequently.

To improve user experience while maintaining security, we can implement a refresh token system. This essentially creates a two-tier authentication system, where a long-lived refresh token is used to obtain short-lived access tokens.

The refresh token can be revoked if needed, allowing for better control over user sessions.

### Refresh Token Management

```go
// internal/adapters/database/sqlc/refresh_token.go
package sqlc

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type RefreshToken struct {
	ID        uuid.UUID `json:"id"`
	UserID    uuid.UUID `json:"user_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	Revoked   bool      `json:"revoked"`
}

const createRefreshToken = `-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (user_id, token, expires_at)
VALUES ($1, $2, $3)
RETURNING id, user_id, token, expires_at, created_at, revoked
`

type CreateRefreshTokenParams struct {
	UserID    uuid.UUID `json:"user_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (q *Queries) CreateRefreshToken(ctx context.Context, arg CreateRefreshTokenParams) (*RefreshToken, error) {
	row := q.db.QueryRowContext(ctx, createRefreshToken, arg.UserID, arg.Token, arg.ExpiresAt)
	var i RefreshToken
	err := row.Scan(
		&i.ID,
		&i.UserID,
		&i.Token,
		&i.ExpiresAt,
		&i.CreatedAt,
		&i.Revoked,
	)
	return &i, err
}

const getRefreshToken = `-- name: GetRefreshToken :one
SELECT id, user_id, token, expires_at, created_at, revoked
FROM refresh_tokens
WHERE token = $1
`

func (q *Queries) GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error) {
	row := q.db.QueryRowContext(ctx, getRefreshToken, token)
	var i RefreshToken
	err := row.Scan(
		&i.ID,
		&i.UserID,
		&i.Token,
		&i.ExpiresAt,
		&i.CreatedAt,
		&i.Revoked,
	)
	return &i, err
}

const revokeRefreshToken = `-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens
SET revoked = true
WHERE token = $1
`

func (q *Queries) RevokeRefreshToken(ctx context.Context, token string) error {
	_, err := q.db.ExecContext(ctx, revokeRefreshToken, token)
	return err
}

```

The main benefits of refresh tokens are that they:

1. Allow access tokens to be short-lived (e.g., 15 minutes), which reduces the risk if they're leaked.
2. Enable longer sessions without requiring frequent logins.
3. Can be revoked server-side if needed, such as on logout or if a security breach is detected.

## User Authentication Handlers

Now let's create our user authentication handler:

```go
// internal/ports/http/handlers/user/user.go

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

```

This handler exposes endpoints for signin, signup, RefreshAccessToken, and RevokeRefreshAccessToken.

## Protecting Routes with Middleware

Now let's test our authentication system and create a middleware to protect routes that require authentication:

```go
// internal/ports/http/middleware/auth.go
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
				"error": "Invalid token claims",
			})
			c.Abort()
			return
		}

		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid user ID in token",
			})
			return
		}

		c.Set("userID", userID)

		c.Next()
	}
}

```

The middleware extracts the JWT token from the Authorization header, validates it, and adds the user ID to the request context. This allows subsequent handlers to access the authenticated user's identity.

### Key Things the Auth Middleware Does

1. Extracting the JWT token from the Authorization header.
2. Validating the token signature and expiration.
3. Adding the authenticated user's ID to the request context.
4. Rejecting requests with invalid or missing tokens.

### Connecting the API and Main Application

Let's connect everything together in our API module:

```go
// cmd/api/api.go

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

	s.Health()
	s.User()

	s.Engine.Run()

	return s
}

func (s *Server) Health() {
	s.Engine.GET("/health", middleware.AuthMiddleware(*s.Env), func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{
			"message": "Server Up!",
		})
	})
}

func (s *Server) User() {
	userHandler := user.NewUserHandler(*s.Env, *s.Queries)

	rg := s.Engine.Group("/user")

	rg.POST("/signup", userHandler.SignUp)
	rg.POST("/signin", userHandler.SignIn)
	rg.POST("/refresh", userHandler.RefreshAccessToken)

	// admin in case of revoking access token
	rg.POST("/revoke-refresh", userHandler.RevokeRefreshAccessToken)
}

```

Now let's connect everything to our main application:

```go
// cmd/main.go

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

func main() {

	db := database.NewPool()

	queries := sqlc.New(db)

	api.API(environmentVariables, queries)

}
```

## Run the Application

We can run the application by running:

```bash
go run cmd/main.go
```

You should see among the output, first:

```text
2026/06/11 16:14:11 database created & is reachable
```

Then lastly:

```text
[GIN-debug] Listening and serving HTTP on :8080
```

## Testing with cURL

```bash
curl -X POST http://localhost:8080/user/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "umohsg.alt@gmail.com",
    "password": "SecureP@ssw0rd!"
  }'
```

We should get the response:

```json
{
  "data": {
    "id": "019eb743-87a6-701b-861a-3339ad2373ce",
    "email": "umohsg.alt@gmail.com",
    "password_hash": "$2a$14$vE3/zq1/WzK3z.uSH4v.9ebvyJfPmAyBZNCLy1Pyr4.ezaX/Zq23q",
    "created_at": {
      "Time": "2026-06-11T16:18:36.709895+01:00",
      "Valid": true
    }
  },
  "message": "user created successfully"
}
```

Next, let's log in with the newly created user:

```bash
curl -X POST http://localhost:8080/user/signin \
  -H "Content-Type: application/json" \
  -d '{
    "email": "umohsg.alt@gmail.com",
    "password": "SecureP@ssw0rd!"
  }'
```

We should get the response:

```json
{
  "data": {
    "id": "019eb743-87a6-701b-861a-3339ad2373ce",
    "email": "umohsg.alt@gmail.com",
    "password_hash": "$2a$14$vE3/zq1/WzK3z.uSH4v.9ebvyJfPmAyBZNCLy1Pyr4.ezaX/Zq23q",
    "created_at": {
      "Time": "2026-06-11T16:18:36.709895+01:00",
      "Valid": true
    }
  },
  "jwt": {
    "refresh_token": "1fe63ff8-30c8-4666-a53d-951401f71216",
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InVtb2hzZy5hbHRAZ21haWwuY29tIiwiZXhwIjoxNzgxMTkzMDAzLCJpYXQiOjE3ODExOTEyMDMsInN1YiI6IjAxOWViNzQzLTg3YTYtNzAxYi04NjFhLTMzMzlhZDIzNzNjZSJ9.RVQk03jen6HzfHnjXkTiD612gMDrNtFsExWKElWElDg"
  },
  "message": "login successful"
}
```

Save the `access_token` and `refresh_token` from the response for the next steps.

Now let's use the access token to access a protected route:

```bash
export ACCESS_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

curl -X GET http://localhost:8080/health \
  -H "Authorization: Bearer $ACCESS_TOKEN"

```

You should get the response:

```json
{
  "message": "Server Up!"
}
```

When your access token expires, refresh it using the refresh token you received during login:

```bash
export REFRESH_TOKEN="c3d4e5f6-7890-...."

curl -X POST http://localhost:8080/user/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "'$REFRESH_TOKEN'"
  }'
```

You should get the response:

```json
{
  "jwt": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InVtb2hzZy5hbHRAZ21haWwuY29tIiwiZXhwIjoxNzgxMTkzMjc0LCJpYXQiOjE3ODExOTE0NzQsInN1YiI6IjAxOWViNzQzLTg3YTYtNzAxYi04NjFhLTMzMzlhZDIzNzNjZSJ9.L6dGe2NbRof2Pjks-83xXZWeFPsqy3Dp06TO2FwNd5Y"
  },
  "message": "success"
}
```

You can also test an invalid token to see the authentication fail:

```bash
curl -X GET http://localhost:8080/api/profile \
  -H "Authorization: Bearer invalid-token"
```

Then lastly, for whatever suspicious reason, you can revoke a user's refresh token:

```bash
export REFRESH_TOKEN="c3d4e5f6-7890-...."

curl -X POST http://localhost:8080/user/revoke-refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "'$REFRESH_TOKEN'"
  }'
```

And you should get a `204 No Content` response.

## Conclusion

In this article, we built a secure authentication system in Go, using JWT and PostgreSQL. The system includes secure password hashing, token-based authentication, refresh token support, middleware-protected routes, and bcrypt hashing to prevent brute-force attacks, amongst others. Security headers and best practices were used to protect us against common web vulnerabilities.

You can checkout the source code on Github here: [umohsamuel/authentication-and-authorization](https://github.com/umohsamuel/authentication-and-authorization), play around with it and lmk what you think.
