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
-- +goose Down
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS user_roles;