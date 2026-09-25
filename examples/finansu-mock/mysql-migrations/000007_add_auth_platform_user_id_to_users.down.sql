ALTER TABLE users
DROP INDEX idx_users_auth_platform_user_id,
DROP COLUMN auth_platform_user_id;
