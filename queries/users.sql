-- name: GetUsers :many
SELECT *
FROM users;
-- name: AddUser :one
INSERT INTO users (email, password_hash)
VALUES ($1, $2)
RETURNING *;
-- name: GetUser :one
SELECT *
FROM users
WHERE email = $1;