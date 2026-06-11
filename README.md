# Golang Authentication System

A secure authentication system built with Go, Gin, JSON Web Tokens (JWT), and PostgreSQL. This project provides an implementation of an authentication flow including token generation, secure password hashing, and token revocation.

## Features

- **Token-Based Authentication**: Implements short-lived access tokens and long-lived refresh tokens.
- **Secure Password Storage**: Utilizes bcrypt for hashing passwords with random salts.
- **Database Integration**: Connects to PostgreSQL and uses sqlc for type-safe database interactions.
- **Middleware Protection**: Secures endpoints using a custom Gin middleware that validates JWT signatures and expiration.
- **Refresh Token Management**: Includes endpoints to generate new access tokens and revoke existing refresh tokens.

## Prerequisites

To run this project locally, you will need:

- Go installed on your machine.
- PostgreSQL running locally or remotely.
- goose installed for database migrations (`go install github.com/pressly/goose/v3/cmd/goose@latest`).

## Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/umohsamuel/authentication-and-authorization.git
cd authentication-authorization
```

### 2. Environment Configuration

Create a `.env` file in the root directory and configure the required environment variables:

```bash
PORT=:8080
JWT_SECRET=your_super_secret_jwt_key
DATABASE_URL=postgres://user:password@localhost:5432/your_database_name
```

### 3. Database Migrations

Apply the database migrations to create the required tables for users and refresh tokens:

```bash
export GOOSE_DRIVER=postgres
export GOOSE_DBSTRING="postgres://user:password@localhost:5432/your_database_name"
export GOOSE_MIGRATION_DIR=./migrations
goose up
```

### 4. Running the Application

Download dependencies and start the application:

```bash
go mod tidy
go run cmd/main.go
```

The server will start on the configured port.

## API Endpoints

### Public Endpoints

- **POST /user/signup**
  Registers a new user and hashes their password.
  Payload: `{"email": "user@example.com", "password": "securepassword"}`

- **POST /user/signin**
  Authenticates a user and returns an access token and a refresh token.
  Payload: `{"email": "user@example.com", "password": "securepassword"}`

- **POST /user/refresh**
  Generates a new access token using a valid refresh token.
  Payload: `{"refresh_token": "your_refresh_token_uuid"}`

- **POST /user/revoke-refresh**
  Revokes a refresh token so it cannot be used again.
  Payload: `{"refresh_token": "your_refresh_token_uuid"}`

### Protected Endpoints

Requests to protected endpoints must include a valid access token in the `Authorization` header:
`Authorization: Bearer <your_access_token>`

- **GET /health**
  Returns a status message if the server is running and the user is authenticated.

## Project Structure

- `cmd/`: Entry point for the application and API server setup.
- `internal/adapters/database/`: Database connection pooling and sqlc models.
- `internal/ports/http/handlers/`: HTTP handlers for the authentication logic.
- `internal/ports/http/middleware/`: Authentication middleware for protecting routes.
- `pkg/env/`: Configuration and environment variable management.
- `pkg/util/`: Helper functions for JWT generation and password hashing.
