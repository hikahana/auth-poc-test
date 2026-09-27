// Package whitelist is the list of email addresses allowed to sign in through
// the platform. Firebase accepts any Google account, and plain gmail.com
// accounts carry no `hd` claim, so this list is the only real gate.
//
// Entries are registered in advance by administrators; there is no
// self-service application. Each entry also carries the platform's own role:
// admins may manage the list. That role says nothing about permissions inside
// the products, which keep their own authorization.
package whitelist

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

type Role string

const (
	RoleMember Role = "member"
	RoleAdmin  Role = "admin"
)

func (r Role) Valid() bool { return r == RoleMember || r == RoleAdmin }

var (
	ErrNotFound  = errors.New("email is not on the whitelist")
	ErrLastAdmin = errors.New("the last administrator cannot be removed or demoted")
)

type Entry struct {
	Email     string    `json:"email"`
	Role      Role      `json:"role"`
	AddedBy   string    `json:"added_by"`
	CreatedAt time.Time `json:"created_at"`
}

type Store struct {
	db *sql.DB
}

func New(db *sql.DB) *Store { return &Store{db: db} }

// Normalize makes lookups case-insensitive: Google reports addresses in lower
// case, but administrators may type them with capitals.
func Normalize(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

const columns = `email, role, added_by, created_at`

func scan(row interface{ Scan(...any) error }) (Entry, error) {
	var e Entry
	err := row.Scan(&e.Email, &e.Role, &e.AddedBy, &e.CreatedAt)
	return e, err
}

func (s *Store) Lookup(ctx context.Context, email string) (Entry, error) {
	e, err := scan(s.db.QueryRowContext(ctx, `SELECT `+columns+` FROM allowed_emails WHERE email = ?`, Normalize(email)))
	if errors.Is(err, sql.ErrNoRows) {
		return Entry{}, ErrNotFound
	}
	return e, err
}

// Add registers an address. Adding one that is already listed leaves the
// existing entry (and its role) unchanged.
func (s *Store) Add(ctx context.Context, email string, role Role, addedBy string) (Entry, error) {
	if !role.Valid() {
		return Entry{}, fmt.Errorf("invalid role %q", role)
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO allowed_emails (email, role, added_by) VALUES (?, ?, ?) ON CONFLICT(email) DO NOTHING`,
		Normalize(email), role, addedBy,
	); err != nil {
		return Entry{}, fmt.Errorf("insert: %w", err)
	}
	return s.Lookup(ctx, email)
}

// lastAdminGuard is true when the row is the only remaining admin. Checking it
// inside the same statement keeps two concurrent requests from removing the
// last two admins at once.
const lastAdminGuard = `role = 'admin' AND (SELECT COUNT(*) FROM allowed_emails WHERE role = 'admin') <= 1`

func (s *Store) SetRole(ctx context.Context, email string, role Role) (Entry, error) {
	if !role.Valid() {
		return Entry{}, fmt.Errorf("invalid role %q", role)
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE allowed_emails SET role = ? WHERE email = ? AND NOT (? = 'member' AND `+lastAdminGuard+`)`,
		role, Normalize(email), role,
	)
	if err != nil {
		return Entry{}, fmt.Errorf("update role: %w", err)
	}
	if err := s.explainNoop(ctx, res, email); err != nil {
		return Entry{}, err
	}
	return s.Lookup(ctx, email)
}

func (s *Store) Remove(ctx context.Context, email string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM allowed_emails WHERE email = ? AND NOT (`+lastAdminGuard+`)`, Normalize(email))
	if err != nil {
		return fmt.Errorf("delete: %w", err)
	}
	return s.explainNoop(ctx, res, email)
}

// explainNoop turns "no row changed" into ErrNotFound or ErrLastAdmin.
func (s *Store) explainNoop(ctx context.Context, res sql.Result, email string) error {
	n, err := res.RowsAffected()
	if err != nil || n > 0 {
		return err
	}
	if _, err := s.Lookup(ctx, email); err != nil {
		return err
	}
	return ErrLastAdmin
}

func (s *Store) List(ctx context.Context) ([]Entry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+columns+` FROM allowed_emails ORDER BY role, email`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	entries := []Entry{}
	for rows.Next() {
		e, err := scan(rows)
		if err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

func (s *Store) CountAdmins(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM allowed_emails WHERE role = 'admin'`).Scan(&n)
	return n, err
}
