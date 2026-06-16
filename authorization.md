So, lets go,

this is part 2 of our authentication & authorization series. in the previous part we implemented an authentication system from scratch in golang with golang gin and postgres sql. now in this part 2 we shall further discuss and see how we can implmen authorization in our system

as usual the requirements for this is
have a working laptop or pc with golang install
have some sort of familairty with golang and sql
have consumed read the frist part of this series (link here)

now. authorization answers the second half of our dilema when we know who you are, surely, we should know what youre allowed to do in our application?

what is authorization?
Authorization determines what an authenticated identity (user, application, or service) can do and which resources it can access within a system.

In most systems, authorization follows authentication (AuthN). Once the system knows who you are, authorization determines what you’re allowed to do.

Authorization ensures that every authenticated identity operates within defined boundaries. Without it, a user who logs in successfully (AuthN) could access all sensitive data and perform any action (AuthZ failure).

What does authorization do in our system?
authorization connects 3 main components

1. users (authenticated entities)
2. permissions (actions they can perform)
3. resources (the things were protecting)

there are mainly 3 ways to implement authorization in a system, we have

1. Role-Based Access Control (RBAC)
   RBAC is the foundational authorization model. It simplifies permission management by assigning permissions to roles (e.g., Admin, Driver, User) and then assigning those roles to users.

How it Works: The system checks the user’s assigned role(s) and aggregates their permissions to determine if the requested action is allowed.

2. Attribute-Based Access Control (ABAC)
   ABAC uses dynamic policies that evaluate attributes of the user, the resource, and the environment to make an access decision.

How it Works: Access is determined by policy expressions that evaluate in real time (e.g., user.department == resource.department, or checking if the current time falls within business hours).

3. Relationship-Based Access Control (ReBAC) and Fine-Grained Authorization (FGA)
   ReBAC bases authorization on the relationships and ownership between a user and a specific resource.

How it Works: The system checks for explicit relationships (e.g., “owner of,” “shared with,” “member of group”) to grant or deny access. Current implementations use graph-based relationship modeling to navigate complex permission chains.

in this guide we will be focusing on only 1 way of implementing authoization which is RBAC

alright, now lets implement rbac into our golang authentication system

first we would need to add some db migrations. in these migrations we create our roles table, we create our permissions table and we have a many-to-many relationship between role and permissions, we thus create our role_permisions table. then we create our user_roles table which is a many to many relationship on users and roles. (writing it intentionally ts so it can be expanciated more)

so lets create a new db migration, lets run

```
goose create create_authorization_tables sql
```

```
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

we also added an insert statement to set a default user role to any existing user who doesnt have a role(i mean, they shouldnt before this migration right?) and then we create an index for faster queries.

then next, lets write all our queries and let sqlc run its magic

```
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

next we generate with

```
sqlc generate
```

great, we have covered most of what we need

next, we need to update our generateaccesstoken function to accept roles, so this can be added to the jwt claims, this way we dont have to always make a call to our db anytime a user hits our RBAC middleware, as that would be very detrimenal. another way we can do this is store the user role and permissions in redis, that way we will get them from redis and proceed that way. and this is the best approach cause this way, we can invalidate permissions and itll update in realtime. whereas for our jwt approach, if we invalidate a entity permission, those permissions still live as long until the jwt access token expires, in our case 10-15 mins. fair tradeoff... but for this guide we will pass the roles to the jwt claims and then access them in our rbac middleware. everything else is the same just the choice of where to store it. for simplicity of this guide, we will stick with this approach.

lets update our generateaccesstoken function to accept and add roles to the claims

```
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

next we will have to update our signup handler function, so that from now when any entity signs up we assign them a role. so just before we send the user created successfuly response, lets add

```
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

next well have to update our signin handler to get the entity roles so we can pass it to the generateaccesstoken function we just modified earlier

```
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

we must also do the same for the refreshaccesstoken handler as it uses the generateaccesstoken function aswell

```
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

finally lets update our api route to reflect out authorization updates

```
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

great, now lets do some testing, you can run the application as usual

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

if we go to an admin only minimum route now as a user

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

you can update your user role from your database, you can use the query tool or update your signup AssignRoleToEntity to create an admin editity, then try the route again, and you should get the response

```
{
  "success": "you have successfully implemented RBAC"
}
```

conclusion

congratulations, if you have made it this far... you have successfully implemented authorization RBAC. phenomenal (glad i could talk you through it, no homo).

this system we built includes... list all it includes clanker,

as usual you can checkout the code on Github here: [umohsamuel/authentication-and-authorization](https://github.com/umohsamuel/authentication-and-authorization), play around with it and lmk what you think.
