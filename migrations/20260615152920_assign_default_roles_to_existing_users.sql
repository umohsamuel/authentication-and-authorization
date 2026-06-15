-- +goose Up
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
-- +goose Down
SELECT 1;