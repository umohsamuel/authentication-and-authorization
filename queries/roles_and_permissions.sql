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