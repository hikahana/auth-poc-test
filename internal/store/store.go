// Package store opens the platform's SQLite database and brings its schema up
// to date. Migrations are append-only; PRAGMA user_version records how many
// have been applied, so existing local databases upgrade in place.
package store

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

var migrations = []string{
	// 1: the pre-registered whitelist.
	`CREATE TABLE IF NOT EXISTS allowed_emails (
		email      TEXT PRIMARY KEY,
		added_by   TEXT NOT NULL,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`,
	// 2: whitelist entries carry the platform's own role (who may manage it).
	`ALTER TABLE allowed_emails ADD COLUMN role TEXT NOT NULL DEFAULT 'member'
		CHECK (role IN ('member', 'admin'))`,
	// 3: products allowed to call /v1/auth/verify. Only a hash of the secret is kept.
	`CREATE TABLE clients (
		id          TEXT PRIMARY KEY,
		name        TEXT NOT NULL UNIQUE,
		secret_hash TEXT NOT NULL,
		is_active   BOOLEAN NOT NULL DEFAULT 1,
		created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`,
	// 4: which login (Firebase UID) has signed in to which product. The
	// platform keeps no session; this record is what lets it tell each
	// product to drop a user's sessions later.
	`CREATE TABLE user_client_links (
		sub           TEXT NOT NULL,
		client_id     TEXT NOT NULL REFERENCES clients(id),
		email         TEXT NOT NULL,
		first_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		last_seen_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (sub, client_id)
	)`,
	// 5: revocation looks links up by email.
	`CREATE INDEX idx_user_client_links_email ON user_client_links (email)`,
}

func Open(path string) (*sql.DB, error) {
	// A single connection keeps PRAGMA state and serialises writes, which is
	// all this small admin-facing service needs from SQLite.
	db, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(1)")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db.SetMaxOpenConns(1)

	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func migrate(db *sql.DB) error {
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}

	for i := version; i < len(migrations); i++ {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, i+1)); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: set version: %w", i+1, err)
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
