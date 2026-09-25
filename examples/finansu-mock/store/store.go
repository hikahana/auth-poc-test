// Package store holds the SQLite version of FinanSu's auth tables
// (mysql/prdDb/02_users.sql, 21_mail_auth.sql, 28_roles.sql, 29_session.sql).
package store

import (
	"context"
	"database/sql"
	"fmt"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

// session keeps FinanSu's "one session per auth record" rule: the real table
// uses auth_id as its primary key, expressed here as a UNIQUE column because
// SQLite only auto-increments an INTEGER PRIMARY KEY.
//
// users.auth_platform_user_id is the one column FinanSu itself would gain
// (see mysql-migrations/).
const schema = `
CREATE TABLE IF NOT EXISTS roles (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	name       TEXT NOT NULL,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS users (
	id                    INTEGER PRIMARY KEY AUTOINCREMENT,
	name                  TEXT NOT NULL,
	bureau_id             INTEGER NOT NULL,
	role_id               INTEGER NOT NULL,
	is_deleted            BOOLEAN NOT NULL DEFAULT false,
	auth_platform_user_id TEXT UNIQUE,
	created_at            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS mail_auth (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	email      TEXT UNIQUE,
	password   TEXT NOT NULL,
	user_id    INTEGER NOT NULL,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS session (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	auth_id      INTEGER NOT NULL UNIQUE,
	user_id      INTEGER NOT NULL,
	access_token TEXT NOT NULL,
	created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`

func Open(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return db, nil
}

// Role ids and names match mysql/prdDb/28_roles.sql.
var roles = []string{"user", "admin", "Finance Director", "Finance Staff"}

type seedUser struct {
	email  string
	name   string
	roleID int
}

var seedUsers = []seedUser{
	{"user@example.com", "user", 1},
	{"admin@example.com", "admin", 2},
}

// Seed inserts roles and sample users (password "password") into an empty database.
func Seed(ctx context.Context, db *sql.DB) error {
	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM roles`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}

	for _, name := range roles {
		if _, err := db.ExecContext(ctx, `INSERT INTO roles (name) VALUES (?)`, name); err != nil {
			return err
		}
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte("password"), 10)
	if err != nil {
		return err
	}
	for _, u := range seedUsers {
		res, err := db.ExecContext(ctx, `INSERT INTO users (name, bureau_id, role_id) VALUES (?, 1, ?)`, u.name, u.roleID)
		if err != nil {
			return err
		}
		userID, _ := res.LastInsertId()
		if _, err := db.ExecContext(ctx, `INSERT INTO mail_auth (email, password, user_id) VALUES (?, ?, ?)`,
			u.email, string(hashed), userID); err != nil {
			return err
		}
	}
	return nil
}
