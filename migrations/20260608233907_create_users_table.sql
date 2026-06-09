-- +goose Up
CREATE TABLE users (
 id uuid PRIMARY KEY DEFAULT uuidv7(),
 email VARCHAR(255) UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
-- +goose Down
DROP TABLE IF EXISTS users