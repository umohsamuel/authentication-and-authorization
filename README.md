# Golang Authentication & Authorization System

A secure authentication and authorization system built with Go, Gin, JSON Web Tokens (JWT), and PostgreSQL. This project provides a complete implementation of authentication (signup, signin, token management) and Role-Based Access Control (RBAC) authorization with roles, permissions, and middleware-enforced access policies.

## Features

### Authentication

- **Token-Based Authentication**: Implements short-lived access tokens and long-lived refresh tokens using JWT.
- **Secure Password Storage**: Utilizes bcrypt for hashing passwords with random salts.
- **Refresh Token Management**: Includes endpoints to generate new access tokens and revoke existing refresh tokens.

### Authorization (RBAC)

- **Role-Based Access Control**: Users are assigned roles (e.g., `super-admin`, `admin`, `user`, `guest`) that determine their access level.
- **Granular Permissions**: Permissions (`create_task`, `read_task`, `update_task`, `delete_task`) are mapped to roles via a many-to-many relationship.
- **Role Middleware**: A dedicated `RoleMiddleware` enforces role requirements on protected route groups.
- **JWT-Embedded Roles**: Roles are included in JWT claims, eliminating per-request database lookups for authorization checks.
- **Default Role Assignment**: New users are automatically assigned the `user` role on signup.

### Infrastructure

- **Database Integration**: Connects to PostgreSQL and uses [sqlc](https://sqlc.dev/) for type-safe database interactions.
- **Middleware Protection**: Secures endpoints using custom Gin middleware that validates JWT signatures, expiration, and role claims.
- **Database Migrations**: Managed with [goose](https://github.com/pressly/goose) for reproducible schema changes.

## Role & Permission Matrix

| Role          | `create_task` | `read_task` | `update_task` | `delete_task` |
| ------------- | :-----------: | :---------: | :-----------: | :-----------: |
| `super-admin` |      ✅       |     ✅      |      ✅       |      ✅       |
| `admin`       |      ❌       |     ✅      |      ✅       |      ✅       |
| `user`        |      ❌       |     ✅      |      ✅       |      ❌       |
| `guest`       |      ❌       |     ✅      |      ❌       |      ❌       |

## Prerequisites

To run this project locally, you will need:

- Go installed on your machine.
- PostgreSQL running locally or remotely.
- goose installed for database migrations (`go install github.com/pressly/goose/v3/cmd/goose@latest`).
- sqlc installed for generating type-safe Go code from SQL (`go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest`).

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

Apply the database migrations to create the required tables for users, refresh tokens, roles, permissions, and their relationships:

```bash
export GOOSE_DRIVER=postgres
export GOOSE_DBSTRING="postgres://user:password@localhost:5432/your_database_name"
export GOOSE_MIGRATION_DIR=./migrations
goose up
```

This will run the following migrations in order:

1. Create the `users` table.
2. Create the `refresh_tokens` table.
3. Create the authorization tables (`roles`, `permissions`, `role_permissions`, `user_roles`).
4. Assign default roles to any existing users.
5. Add a composite index on `user_roles` for query performance.

### 4. Running the Application

Download dependencies and start the application:

```bash
go mod tidy
go run cmd/main.go
```

The server will start on the configured port.

## API Endpoints

### Public Endpoints (`/auth`)

- **POST /auth/signup**
  Registers a new user, hashes their password, and assigns the default `user` role.
  Payload: `{"email": "user@example.com", "password": "securepassword"}`

- **POST /auth/signin**
  Authenticates a user and returns an access token (with embedded roles) and a refresh token.
  Payload: `{"email": "user@example.com", "password": "securepassword"}`

- **POST /auth/refresh**
  Generates a new access token using a valid refresh token.
  Payload: `{"refresh_token": "your_refresh_token_uuid"}`

- **POST /auth/revoke-refresh**
  Revokes a refresh token so it cannot be used again.
  Payload: `{"refresh_token": "your_refresh_token_uuid"}`

### Protected Endpoints (`/api/v1`)

Requests to protected endpoints must include a valid access token in the `Authorization` header:
`Authorization: Bearer <your_access_token>`

- **GET /api/v1/health**
  Returns a status message if the server is running and the user is authenticated.

### Admin-Only Endpoints (`/api/v1/admin`)

These endpoints require both authentication **and** an `admin` or `super-admin` role:

- **GET /api/v1/admin/test**
  Returns a success message confirming the user has the required role. Used to verify RBAC is working.

## Project Structure

```
.
├── cmd/
│   ├── api/
│   │   └── api.go                 # API server, route definitions, and middleware wiring
│   └── main.go                    # Application entry point
├── internal/
│   ├── adapters/
│   │   └── database/              # Database connection and sqlc-generated models
│   └── ports/
│       └── http/
│           ├── handlers/          # HTTP handlers (signup, signin, token refresh, etc.)
│           └── middleware/        # AuthMiddleware (JWT validation) & RoleMiddleware (RBAC)
├── migrations/                    # Goose SQL migration files
├── queries/                       # SQL queries used by sqlc to generate Go code
├── pkg/
│   ├── env/                       # Configuration and environment variable management
│   └── util/                      # Helper functions for JWT generation/validation and password hashing
├── sqlc.yaml                      # sqlc configuration
├── go.mod
└── go.sum
```

## How It Works

### Authentication Flow

1. **Signup**: User registers with email and password → password is hashed with bcrypt → user is stored in the database → default `user` role is assigned.
2. **Signin**: User provides credentials → password is verified → user roles are fetched from the database → an access token (with roles embedded in claims) and a refresh token are generated.
3. **Token Refresh**: A valid refresh token is exchanged for a new access token (with current roles).
4. **Token Revocation**: A refresh token can be revoked to prevent further use.

### Authorization Flow

1. **AuthMiddleware** extracts and validates the JWT from the `Authorization` header, then sets the `userID` and `roles` in the Gin context.
2. **RoleMiddleware** reads the roles from the Gin context and checks if the user holds at least one of the required roles for the route group.
3. If the user lacks the required role, a `403 Forbidden` response is returned.

## Related Articles

- **Part 1 – Authentication**: [Build a Secure Authentication System in Golang with Gin, JWT, and Postgres](https://www.umohsg.com/blog/build-a-secure-authentication-system-in-golang-with-gin-jwt-and-postgres-48f2e823-f2c3-46c7-a861-ec44e806c38b)
- **Part 2 – Authorization**: [Implement Authorization with Role-Based Access Control (RBAC) in Golang](https://www.umohsg.com/blog/implement-authorization-with-role-based-access-control-rbac-in-golang-f951adce-6292-48d4-b83e-cf4a299cc7be)
