// Package whitelist implements the access-control mechanism Firebase Auth
// cannot provide on its own: restricting login to a specific set of email
// addresses. Google's `hd` claim only exists for Workspace/Cloud-org accounts,
// so for plain gmail.com addresses this whitelist is the only real gate.
package whitelist

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusRejected Status = "rejected"
)

type Entry struct {
	Email      string
	Status     Status
	ApprovedBy string
	CreatedAt  time.Time
	ApprovedAt sql.NullTime
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
CREATE TABLE IF NOT EXISTS whitelist (
	email       TEXT PRIMARY KEY,
	status      TEXT NOT NULL DEFAULT 'pending',
	approved_by TEXT,
	created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	approved_at DATETIME
);
`

// EnsureEntry returns the existing whitelist entry for email, or creates one
// with status=pending if this is the first time we've seen it. This lets new
// Google sign-ins register a pending request without a separate signup step.
func (s *Store) EnsureEntry(ctx context.Context, email string) (Entry, error) {
	entry, err := s.Get(ctx, email)
	if err == nil {
		return entry, nil
	}
	if err != sql.ErrNoRows {
		return Entry{}, err
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO whitelist (email, status) VALUES (?, ?)`,
		email, StatusPending,
	)
	if err != nil {
		return Entry{}, fmt.Errorf("insert pending entry: %w", err)
	}

	return s.Get(ctx, email)
}

func (s *Store) Get(ctx context.Context, email string) (Entry, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT email, status, COALESCE(approved_by, ''), created_at, approved_at
		 FROM whitelist WHERE email = ?`, email)

	var e Entry
	var status string
	if err := row.Scan(&e.Email, &status, &e.ApprovedBy, &e.CreatedAt, &e.ApprovedAt); err != nil {
		return Entry{}, err
	}
	e.Status = Status(status)
	return e, nil
}

func (s *Store) List(ctx context.Context, statusFilter Status) ([]Entry, error) {
	query := `SELECT email, status, COALESCE(approved_by, ''), created_at, approved_at FROM whitelist`
	args := []any{}
	if statusFilter != "" {
		query += ` WHERE status = ?`
		args = append(args, string(statusFilter))
	}
	query += ` ORDER BY created_at DESC`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []Entry
	for rows.Next() {
		var e Entry
		var status string
		if err := rows.Scan(&e.Email, &status, &e.ApprovedBy, &e.CreatedAt, &e.ApprovedAt); err != nil {
			return nil, err
		}
		e.Status = Status(status)
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// SetStatus approves or rejects a pending (or existing) entry. approvedBy
// should identify the admin/operator making the decision, for audit purposes.
func (s *Store) SetStatus(ctx context.Context, email string, status Status, approvedBy string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE whitelist SET status = ?, approved_by = ?, approved_at = CURRENT_TIMESTAMP
		 WHERE email = ?`,
		string(status), approvedBy, email,
	)
	if err != nil {
		return fmt.Errorf("update status: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
