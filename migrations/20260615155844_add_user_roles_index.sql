-- +goose Up
CREATE INDEX idx_user_roles_user_id_role_id ON user_roles (user_id, role_id);
-- +goose Down
SELECT 'down SQL query';
DROP INDEX IF EXISTS idx_user_roles_user_id_role_id;