# Implement Authorization with Role-Based Access Control (RBAC) in Golang using Gin, JWT, and Postgres

This is part 2 of our authentication and authorization series. In the previous part, we implemented an authentication system from scratch in Golang with Gin and PostgreSQL. Now in this part, we will go further and see how we can implement authorization in our system.

## Prerequisites

The requirements to follow along are:

1. A working laptop or PC with Golang installed.
2. Some familiarity with Golang and SQL.
3. Having read the first part of this series ([link here](https://www.umohsg.com/blog/build-a-secure-authentication-system-in-golang-with-gin-jwt-and-postgres-48f2e823-f2c3-46c7-a861-ec44e806c38b)).

## What is Authorization?

Authorization answers the second half of our dilemma. When we know who you are, surely, we should know what you're allowed to do in our system?

Authorization determines what an authenticated identity (user, application, or service) can do and which resources it can access within a system. It ensures that every authenticated identity operates within defined boundaries. Without it, a user who logs in successfully could access all sensitive data and perform any action.

### What Does Authorization Do in Our System?

Authorization connects three main components:

1. **Users** (authenticated entities)
2. **Permissions** (actions they can perform)
3. **Resources** (the things we're protecting)

### Common Authorization Models

There are mainly three ways to implement authorization in a system:

1. **Role-Based Access Control (RBAC)**
   RBAC is the foundational authorization model. It simplifies permission management by assigning permissions to roles (e.g., Admin, Driver, User) and then assigning those roles to users.

   **How it works**: The system checks the user's assigned role(s) and aggregates their permissions to determine if the requested action is allowed.

2. **Attribute-Based Access Control (ABAC)**
   ABAC uses dynamic policies that evaluate attributes of the user, the resource, and the environment to make an access decision.

   **How it works**: Access is determined by policy expressions that evaluate in real time (e.g., `user.department == resource.department`, or checking if the current time falls within business hours).

3. **Relationship-Based Access Control (ReBAC) and Fine-Grained Authorization (FGA)**
   ReBAC bases authorization on the relationships and ownership between a user and a specific resource.

   **How it works**: The system checks for explicit relationships (e.g., "owner of," "shared with," "member of group") to grant or deny access. Current implementations use graph-based relationship modeling to navigate complex permission chains.

In this guide, we will be focusing on implementing RBAC. It's the most common and straightforward to implement, making it a solid starting point.

## Database Migrations for RBAC

Now, let's implement RBAC into our Golang authentication system.

First, we need to add some database migrations. In these migrations, we will create:

- A **roles** table to define the available roles.
- A **permissions** table to define the available permissions.
- A **role_permissions** table to establish the many-to-many relationship between roles and permissions.
- A **user_roles** table to establish the many-to-many relationship between users and roles.

So let's create a new database migration:

```bash
goose create create_authorization_tables sql
```

Paste this into the generated migration file:

```sql
-- migrations/..._create_authorization_tables.sql

-- +goose Up
-- role
CREATE TABLE roles (
  id SMALLSERIAL PRIMARY KEY,
  name VARCHAR(50) UNIQUE NOT NULL
);
INSERT INTO roles (name)
VALUES ('super-admin'),
  ('admin'),
  ('user'),
  ('guest');
--permissions
CREATE TABLE permissions (
  id SMALLSERIAL PRIMARY KEY,
  name VARCHAR(50) UNIQUE NOT NULL
);
INSERT INTO permissions (name)
VALUES ('create_task'),
  ('read_task'),
  ('update_task'),
  ('delete_task');
-- role permissions
CREATE TABLE role_permissions (
  role_id SMALLINT NOT NULL,
  permission_id SMALLINT NOT NULL,
  PRIMARY KEY (role_id, permission_id),
  FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
  FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
);
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id,
  p.id
FROM (
    VALUES ('super-admin', 'create_task'),
      ('super-admin', 'read_task'),
      ('super-admin', 'update_task'),
      ('super-admin', 'delete_task'),
      ('admin', 'read_task'),
      ('admin', 'update_task'),
      ('admin', 'delete_task'),
      ('user', 'read_task'),
      ('user', 'update_task'),
      ('guest', 'read_task')
  ) AS mappings(role_name, permission_name)
  JOIN roles r ON r.name = mappings.role_name
  JOIN permissions p ON p.name = mappings.permission_name;
-- user roles
CREATE TABLE user_roles (
  user_id UUID NOT NULL,
  role_id SMALLINT NOT NULL,
  PRIMARY KEY (user_id, role_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);
INSERT INTO user_roles (user_id, role_id)
SELECT u.id,
 r.id
FROM users u
 CROSS JOIN roles r
WHERE r.name = 'user'
 AND NOT EXISTS (
  SELECT 1
  FROM user_roles ur
  WHERE ur.user_id = u.id
   AND ur.role_id = r.id
 );
CREATE INDEX idx_user_roles_user_id_role_id ON user_roles (user_id, role_id);
-- +goose Down
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS user_roles;
DROP INDEX IF EXISTS idx_user_roles_user_id_role_id;
```

We also added an insert statement to set a default "user" role to any existing user who doesn't have a role (I mean, they shouldn't before this migration, right?). We then create an index for faster queries.

Now apply the migration:

```bash
goose up
```

## RBAC Queries

Next, let's write all our queries and let sqlc run its magic:

```sql
-- queries/authorization.sql

-- name: GetRoles :many
SELECT *
FROM roles;
-- name: GetPermissions :many
SELECT *
FROM permissions;
-- name: GetEntityRoles :many
SELECT r.name
FROM user_roles ur
 JOIN roles r ON r.id = ur.role_id
WHERE ur.user_id = $1;
-- name: GetRolePermissions :many
SELECT p.name
FROM role_permissions rp
 JOIN permissions p ON p.id = rp.permission_id
WHERE rp.role_id = $1;
-- name: GetRolePermissionsByRoleName :many
SELECT p.name
FROM roles r
 JOIN role_permissions rp ON rp.role_id = r.id
 JOIN permissions p ON p.id = rp.permission_id
WHERE r.name = $1;
-- name: GetEntityRolesPermissions :many
SELECT DISTINCT p.name
FROM user_roles ur
 JOIN role_permissions rp ON rp.role_id = ur.role_id
 JOIN permissions p ON p.id = rp.permission_id
WHERE ur.user_id = $1;
-- name: AssignRoleToEntity :exec
INSERT INTO user_roles (user_id, role_id)
SELECT $1,
 id
FROM roles
WHERE name = $2;
-- name: RevokeRoleFromEntity :exec
DELETE FROM user_roles
WHERE user_id = $1
 AND role_id = (
  SELECT id
  FROM roles
  WHERE name = $2
 );
-- name: RemoveAllEntityRoles :exec
DELETE FROM user_roles
WHERE user_id = $1;
```

Then generate the Go code with:

```bash
sqlc generate
```

Great, we have covered most of what we need.

## Adding Roles to JWT Claims

Next, we need to update our `GenerateAccessToken` function to accept roles so they can be added to the JWT claims. This way, we don't have to make a call to our database every time a user hits our RBAC middleware, as that would be very detrimental to performance.

### A Note on Alternative Approaches

Another way we can do this is to store the user roles and permissions in Redis.

That way, we will get them from Redis and proceed accordingly. This is actually the better approach because we can invalidate permissions and it will update in real time.

Whereas with our JWT approach, if we invalidate an entity's permissions, those permissions still live until the JWT access token expires, in our case 10-15 minutes.

Now you understand the tradeoff, but for simplicity of this guide, we will pass the roles to the JWT claims and then access them in our RBAC middleware. Everything else is the same, just the choice of where to store it.

### Updating GenerateAccessToken

Let's update our `GenerateAccessToken` function to accept and add roles to the claims:

```go
// pkg/util/auth.go

func GenerateAccessToken(user sqlc.User, roles []string, jwtSecret []byte, accessTokenTTL time.Duration) (string, error) {
	expirationTime := time.Now().UTC().Add(accessTokenTTL)

	claims := jwt.MapClaims{
		"sub":   user.ID.String(),
		"email": user.Email,
		"roles": roles,
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
```

## Updating the Authentication Handlers

### Updating the SignUp Handler

We need to update our signup handler so that when any entity signs up, we assign them a default role. Just before we send the "user created successfully" response, let's add:

```go
// internal/ports/http/handlers/user/user.go

	err = h.queries.AssignRoleToEntity(c, sqlc.AssignRoleToEntityParams{
		UserID: user.ID,
		Name:   "user",
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": err.Error(),
		})
		return
	}
```

### Updating the SignIn Handler

Next, we'll have to update our signin handler to get the entity roles so we can pass them to the `GenerateAccessToken` function we just modified:

```go
// internal/ports/http/handlers/user/user.go

	roles, err := h.queries.GetEntityRoles(c, user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, "error")
		return
	}

	token, err := util.GenerateAccessToken(*user, roles, []byte(h.environmentVariables.Authentication.JWT_SECRET), 30*time.Minute)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "failed to generate access token",
		})
		return
	}
```

### Updating the RefreshAccessToken Handler

We must also do the same for the `RefreshAccessToken` handler, as it uses the `GenerateAccessToken` function as well:

```go
// internal/ports/http/handlers/user/user.go

	roles, err := h.queries.GetEntityRoles(c, user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, "error")
		return
	}

	accessToken, err := util.GenerateAccessToken(*user, roles, []byte(h.environmentVariables.Authentication.JWT_SECRET), 30*time.Minute)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "failed to generate access token",
		})
		return
	}
```

## Updating the Auth Middleware

Now that our JWT tokens contain role claims, we need to update our `AuthMiddleware` to extract and set the roles from the token. We also need a new `RoleMiddleware` that will check if a user has the required roles before granting access to a route.

### Updated AuthMiddleware

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
```

So now, we also extract roles from the JWT claims (since we added them in our updated `GenerateAccessToken`) and we set them as well in the Gin context, easy.

### RoleMiddleware

Since `AuthMiddleware` runs first and sets the user's roles in the Gin context, our `RoleMiddleware` can simply read them and check if the user has the required roles. Now, let's create it:

```go
// internal/ports/http/middleware/auth.go

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
```

This middleware:

1. Retrieves the user's roles from the Gin context (remember we set them in the `AuthMiddleware`).
2. Loops through the user's roles and checks if any match the required roles for the route.
3. If the user has at least one of the required roles, the request proceeds. Otherwise, we return a `403 Forbidden` response.

## Updating the API Routes

Finally, let's update our API routes to reflect our authorization updates:

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
```

I updated the route structure a little, so it's a bit different from Part 1:

- **Public routes** (`/auth/*`) handle signup, signin, and token management.
- **Protected routes** (`/api/v1/*`) use the `AuthMiddleware`, so you must be authenticated to access them.
- **Admin routes** (`/api/v1/admin/*`) add an extra layer with `RoleMiddleware`, so only users with the `super-admin` or `admin` role can access them.

## Run the Application

Let's do some testing. You can run the application in your terminal with:

```bash
go run cmd/main.go
```

## Testing with cURL

If we go to an admin-only route now as a regular user:

```bash
export ACCESS_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

curl -X GET http://localhost:8080/api/v1/admin/test \
  -H "Authorization: Bearer $ACCESS_TOKEN"

```

You should get the response 403:

```json
{
  "error": "Forbidden"
}
```

You can update your user role from your database using a query tool, or update your signup `AssignRoleToEntity` to create an admin entity. Then try the route again, and you should get the response:

```json
{
  "success": "you have successfully implemented RBAC"
}
```

## Conclusion

Congratulations, if you have made it this far, you have successfully implemented RBAC authorization. This system we built includes:

1. Database schema for roles, permissions, and their relationships.
2. Many-to-many mappings between roles and permissions, and between users and roles.
3. Default role assignment on user signup.
4. Role-based middleware to protect routes based on required roles.
5. A structured API with separated public routes and protected routes.

As usual, you can checkout the source code on Github here: [umohsamuel/authentication-and-authorization](https://github.com/umohsamuel/authentication-and-authorization), play around with it and lmk what you think.
