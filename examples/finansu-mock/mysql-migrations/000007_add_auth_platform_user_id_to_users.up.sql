ALTER TABLE users
ADD COLUMN auth_platform_user_id varchar(255) NULL,
ADD UNIQUE INDEX idx_users_auth_platform_user_id (auth_platform_user_id);
