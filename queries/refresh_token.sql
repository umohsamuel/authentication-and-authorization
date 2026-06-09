-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (user_id, token, expires_at)
VALUES ($1, $2, $3)
RETURNING *;
-- name: GetRefreshToken :one
SELECT *
FROM refresh_tokens
WHERE token = $1;
-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens
SET revoked = true
WHERE token = $1;