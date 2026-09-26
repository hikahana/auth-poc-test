// Package whitelist is the list of email addresses allowed to sign in through
// the platform. Firebase accepts any Google account, and plain gmail.com
// accounts carry no `hd` claim, so this list is the only real gate.
//
// Entries are registered in advance by operators; there is no self-service
// application. An address that is not on the list is simply refused.
package whitelist

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var ErrNotFound = errors.New("email is not on the whitelist")

type Entry struct {
	Email     string    `json:"email"`
	AddedBy   string    `json:"added_by"`
	CreatedAt time.Time `json:"created_at"`
}

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate schema: %w", err)
	}

	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

const schema = `
CREATE TABLE IF NOT EXISTS allowed_emails (
	email      TEXT PRIMARY KEY,
	added_by   TEXT NOT NULL,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`

// normalize makes lookups case-insensitive: Google reports addresses in lower
// case, but operators may type them with capitals.
func normalize(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func (s *Store) IsAllowed(ctx context.Context, email string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM allowed_emails WHERE email = ?`, normalize(email)).Scan(&n)
	return n > 0, err
}

// Add registers an address. Adding one that is already listed is not an error.
func (s *Store) Add(ctx context.Context, email, addedBy string) (Entry, error) {
	email = normalize(email)
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO allowed_emails (email, added_by) VALUES (?, ?) ON CONFLICT(email) DO NOTHING`,
		email, addedBy,
	); err != nil {
		return Entry{}, fmt.Errorf("insert: %w", err)
	}

	var e Entry
	err := s.db.QueryRowContext(ctx,
		`SELECT email, added_by, created_at FROM allowed_emails WHERE email = ?`, email,
	).Scan(&e.Email, &e.AddedBy, &e.CreatedAt)
	return e, err
}

func (s *Store) Remove(ctx context.Context, email string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM allowed_emails WHERE email = ?`, normalize(email))
	if err != nil {
		return fmt.Errorf("delete: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) List(ctx context.Context) ([]Entry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT email, added_by, created_at FROM allowed_emails ORDER BY email`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	entries := []Entry{}
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.Email, &e.AddedBy, &e.CreatedAt); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}
