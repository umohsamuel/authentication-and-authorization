-- +goose Up
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
DROP TABLE IF EXISTS refresh_tokens;
DROP INDEX IF EXISTS idx_refresh_tokens_token;