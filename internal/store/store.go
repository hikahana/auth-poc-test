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
