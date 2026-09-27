// Package whitelist is the platform's list of people allowed to sign in.
//
// Only NUTFes addresses (…@gmail.com local parts ending in ".nutfes") are
// eligible. An eligible address is registered automatically as a member the
// first time it signs in; administrators disable people instead of deleting
// them, so a disabled person is not re-registered on their next login.
//
// Each entry also carries the platform's own role: admins may manage the
// platform. That role says nothing about permissions inside the products,
// which keep their own authorization.
package whitelist

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// EligibleSuffix is the only kind of address allowed through. Anyone can
// create such a Gmail address, so this is a coarse filter; administrators
// disable impostors that auto-registration lets in.
const EligibleSuffix = ".nutfes@gmail.com"

// AddedByAutoRegistration marks entries created by a first login rather
// than by an administrator.
const AddedByAutoRegistration = "auto"

type Role string

const (
	RoleMember Role = "member"
	RoleAdmin  Role = "admin"
)

func (r Role) Valid() bool { return r == RoleMember || r == RoleAdmin }

var (
	ErrNotFound    = errors.New("email is not on the whitelist")
	ErrNotEligible = errors.New("only addresses ending in " + EligibleSuffix + " can sign in")
	ErrLastAdmin   = errors.New("the last active administrator cannot be disabled or demoted")
)

type Entry struct {
	Email      string     `json:"email"`
	Role       Role       `json:"role"`
	Active     bool       `json:"active"`
	AddedBy    string     `json:"added_by"`
	CreatedAt  time.Time  `json:"created_at"`
	DisabledAt *time.Time `json:"disabled_at"`
	DisabledBy string     `json:"disabled_by"`
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

func Eligible(email string) bool {
	e := Normalize(email)
	return strings.HasSuffix(e, EligibleSuffix) && len(e) > len(EligibleSuffix)
}

var entryYearPattern = regexp.MustCompile(`^(\d{2})\.`)

// EntryYear reads the two-digit year NUTFes addresses start with
// ("22.h.hanada.nutfes@gmail.com" -> 22).
func EntryYear(email string) (int, bool) {
	m := entryYearPattern.FindStringSubmatch(Normalize(email))
	if m == nil {
		return 0, false
	}
	y, _ := strconv.Atoi(m[1])
	return y, true
}

const columns = `email, role, added_by, created_at, disabled_at, disabled_by`

func scan(row interface{ Scan(...any) error }) (Entry, error) {
	var e Entry
	var disabledAt sql.NullTime
	err := row.Scan(&e.Email, &e.Role, &e.AddedBy, &e.CreatedAt, &disabledAt, &e.DisabledBy)
	if disabledAt.Valid {
		e.DisabledAt = &disabledAt.Time
	}
	e.Active = !disabledAt.Valid
	return e, err
}

func (s *Store) Lookup(ctx context.Context, email string) (Entry, error) {
	e, err := scan(s.db.QueryRowContext(ctx, `SELECT `+columns+` FROM allowed_emails WHERE email = ?`, Normalize(email)))
	if errors.Is(err, sql.ErrNoRows) {
		return Entry{}, ErrNotFound
	}
	return e, err
}

// Add registers an eligible address. Adding one that is already listed
// leaves the existing entry (its role and whether it is disabled) unchanged.
func (s *Store) Add(ctx context.Context, email string, role Role, addedBy string) (Entry, error) {
	if !role.Valid() {
		return Entry{}, fmt.Errorf("invalid role %q", role)
	}
	if !Eligible(email) {
		return Entry{}, ErrNotEligible
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO allowed_emails (email, role, added_by) VALUES (?, ?, ?) ON CONFLICT(email) DO NOTHING`,
		Normalize(email), role, addedBy,
	); err != nil {
		return Entry{}, fmt.Errorf("insert: %w", err)
	}
	return s.Lookup(ctx, email)
}

// EnsureMember is the automatic registration on first login: it adds an
// eligible address as a member if it is not listed yet, and otherwise returns
// the existing entry — which may be disabled.
func (s *Store) EnsureMember(ctx context.Context, email string) (Entry, error) {
	return s.Add(ctx, email, RoleMember, AddedByAutoRegistration)
}

// lastAdminGuard is true when the row is the only remaining active admin.
// Checking it inside the same statement keeps two concurrent requests from
// taking out the last two admins at once.
const lastAdminGuard = `role = 'admin' AND disabled_at IS NULL AND
	(SELECT COUNT(*) FROM allowed_emails WHERE role = 'admin' AND disabled_at IS NULL) <= 1`

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

// Disable keeps the person out from now on. Disabling an already disabled
// entry is not an error, so a bulk run can be repeated.
func (s *Store) Disable(ctx context.Context, email, by string) (Entry, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE allowed_emails SET disabled_at = CURRENT_TIMESTAMP, disabled_by = ?
		 WHERE email = ? AND disabled_at IS NULL AND NOT (`+lastAdminGuard+`)`,
		by, Normalize(email),
	)
	if err != nil {
		return Entry{}, fmt.Errorf("disable: %w", err)
	}
	if err := s.explainNoop(ctx, res, email); err != nil {
		return Entry{}, err
	}
	return s.Lookup(ctx, email)
}

func (s *Store) Enable(ctx context.Context, email string) (Entry, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE allowed_emails SET disabled_at = NULL, disabled_by = '' WHERE email = ?`, Normalize(email))
	if err != nil {
		return Entry{}, fmt.Errorf("enable: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return Entry{}, ErrNotFound
	}
	return s.Lookup(ctx, email)
}

// explainNoop turns "no row changed" into ErrNotFound, nothing (the entry was
// already disabled), or ErrLastAdmin.
func (s *Store) explainNoop(ctx context.Context, res sql.Result, email string) error {
	n, err := res.RowsAffected()
	if err != nil || n > 0 {
		return err
	}
	e, err := s.Lookup(ctx, email)
	if err != nil {
		return err
	}
	if !e.Active {
		return nil
	}
	return ErrLastAdmin
}

func (s *Store) List(ctx context.Context) ([]Entry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+columns+` FROM allowed_emails ORDER BY disabled_at IS NOT NULL, role, email`)
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

func (s *Store) CountActiveAdmins(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM allowed_emails WHERE role = 'admin' AND disabled_at IS NULL`).Scan(&n)
	return n, err
}

// BulkCriteria selects people to disable at once. Set fields are combined
// with AND; unset (nil) fields do not filter.
type BulkCriteria struct {
	// EntryYearFrom / EntryYearTo bound the two-digit year at the start of the
	// address, inclusive. Addresses without such a prefix never match a year bound.
	EntryYearFrom, EntryYearTo *int
	// RegisteredFrom (inclusive) / RegisteredBefore (exclusive) bound when the
	// entry was created — for auto-registered people, their first login.
	RegisteredFrom, RegisteredBefore *time.Time
}

func (c BulkCriteria) Empty() bool {
	return c.EntryYearFrom == nil && c.EntryYearTo == nil && c.RegisteredFrom == nil && c.RegisteredBefore == nil
}

func (c BulkCriteria) matches(e Entry) bool {
	if c.EntryYearFrom != nil || c.EntryYearTo != nil {
		y, ok := EntryYear(e.Email)
		if !ok || (c.EntryYearFrom != nil && y < *c.EntryYearFrom) || (c.EntryYearTo != nil && y > *c.EntryYearTo) {
			return false
		}
	}
	if c.RegisteredFrom != nil && e.CreatedAt.Before(*c.RegisteredFrom) {
		return false
	}
	if c.RegisteredBefore != nil && !e.CreatedAt.Before(*c.RegisteredBefore) {
		return false
	}
	return true
}

// SelectForBulkDisable lists the active members matching c. Administrators
// are never selected: a bulk run must not lock the admins out.
func (s *Store) SelectForBulkDisable(ctx context.Context, c BulkCriteria) ([]Entry, error) {
	if c.Empty() {
		return nil, errors.New("at least one condition is required")
	}
	all, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	selected := []Entry{}
	for _, e := range all {
		if e.Active && e.Role == RoleMember && c.matches(e) {
			selected = append(selected, e)
		}
	}
	return selected, nil
}
