// Package clients manages the products (GM2, FinanSu, ...) allowed to call the
// platform, and records which login has signed in to which product.
package clients

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

var (
	ErrNotFound           = errors.New("no such client")
	ErrDuplicateName      = errors.New("a client with this name already exists")
	ErrInvalidCredentials = errors.New("invalid client credentials")
	ErrInvalidRevokeURL   = errors.New("revoke_url must be an http(s) URL")
)

type Client struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	RevokeURL string    `json:"revoke_url"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
}

// Target is one place a user's sessions must be dropped: a product the
// login has signed in to, with what is needed to notify it.
type Target struct {
	Sub        string
	Email      string
	ClientID   string
	ClientName string
	RevokeURL  string
	// SigningKey is the stored hash of the product's secret. The product can
	// derive the same value from its secret, so notifications can be signed
	// without the platform ever keeping the secret itself.
	SigningKey string
}

// Login is one (login, product) pair: this Firebase UID has signed in to
// this product at least once.
type Login struct {
	Sub         string    `json:"sub"`
	Email       string    `json:"email"`
	ClientID    string    `json:"client_id"`
	ClientName  string    `json:"client_name"`
	FirstSeenAt time.Time `json:"first_seen_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
}

type Store struct {
	db *sql.DB
}

func New(db *sql.DB) *Store { return &Store{db: db} }

func randomToken(prefix string, n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// HashSecret is a plain SHA-256: secrets are 256-bit random values, so a slow
// password hash would add latency to every verify call without adding safety.
func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

const columns = `id, name, revoke_url, is_active, created_at`

func scan(row interface{ Scan(...any) error }) (Client, error) {
	var c Client
	err := row.Scan(&c.ID, &c.Name, &c.RevokeURL, &c.IsActive, &c.CreatedAt)
	return c, err
}

// ValidRevokeURL accepts an empty string (notifications not set up yet) or an
// absolute http(s) URL.
func ValidRevokeURL(raw string) bool {
	if raw == "" {
		return true
	}
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// Create registers a product and returns its secret. The secret is shown
// only here; afterwards only its hash exists.
func (s *Store) Create(ctx context.Context, name, revokeURL string) (Client, string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Client{}, "", errors.New("name is required")
	}
	if !ValidRevokeURL(revokeURL) {
		return Client{}, "", ErrInvalidRevokeURL
	}
	id, err := randomToken("cl_", 12)
	if err != nil {
		return Client{}, "", err
	}
	secret, err := randomToken("cs_", 32)
	if err != nil {
		return Client{}, "", err
	}

	_, err = s.db.ExecContext(ctx, `INSERT INTO clients (id, name, secret_hash, revoke_url) VALUES (?, ?, ?, ?)`,
		id, name, HashSecret(secret), revokeURL)
	if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed: clients.name") {
		return Client{}, "", ErrDuplicateName
	}
	if err != nil {
		return Client{}, "", fmt.Errorf("insert client: %w", err)
	}

	c, err := s.Get(ctx, id)
	return c, secret, err
}

func (s *Store) Get(ctx context.Context, id string) (Client, error) {
	c, err := scan(s.db.QueryRowContext(ctx, `SELECT `+columns+` FROM clients WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Client{}, ErrNotFound
	}
	return c, err
}

func (s *Store) FindByName(ctx context.Context, name string) (Client, error) {
	c, err := scan(s.db.QueryRowContext(ctx, `SELECT `+columns+` FROM clients WHERE name = ?`, strings.TrimSpace(name)))
	if errors.Is(err, sql.ErrNoRows) {
		return Client{}, ErrNotFound
	}
	return c, err
}

// Authenticate checks a product's credentials. Unknown, wrong and deactivated
// clients all get the same error so callers cannot probe which is which.
func (s *Store) Authenticate(ctx context.Context, id, secret string) (Client, error) {
	var c Client
	var hash string
	err := s.db.QueryRowContext(ctx, `SELECT `+columns+`, secret_hash FROM clients WHERE id = ?`, id).
		Scan(&c.ID, &c.Name, &c.RevokeURL, &c.IsActive, &c.CreatedAt, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		return Client{}, ErrInvalidCredentials
	}
	if err != nil {
		return Client{}, err
	}
	if subtle.ConstantTimeCompare([]byte(hash), []byte(HashSecret(secret))) != 1 || !c.IsActive {
		return Client{}, ErrInvalidCredentials
	}
	return c, nil
}

// RotateSecret issues a new secret; the old one stops working immediately.
func (s *Store) RotateSecret(ctx context.Context, id string) (string, error) {
	secret, err := randomToken("cs_", 32)
	if err != nil {
		return "", err
	}
	res, err := s.db.ExecContext(ctx, `UPDATE clients SET secret_hash = ? WHERE id = ?`, HashSecret(secret), id)
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", ErrNotFound
	}
	return secret, nil
}

// Update changes whichever of isActive / revokeURL is non-nil.
func (s *Store) Update(ctx context.Context, id string, isActive *bool, revokeURL *string) (Client, error) {
	if revokeURL != nil && !ValidRevokeURL(*revokeURL) {
		return Client{}, ErrInvalidRevokeURL
	}
	c, err := s.Get(ctx, id)
	if err != nil {
		return Client{}, err
	}
	if isActive != nil {
		c.IsActive = *isActive
	}
	if revokeURL != nil {
		c.RevokeURL = *revokeURL
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE clients SET is_active = ?, revoke_url = ? WHERE id = ?`,
		c.IsActive, c.RevokeURL, id); err != nil {
		return Client{}, err
	}
	return s.Get(ctx, id)
}

func (s *Store) List(ctx context.Context) ([]Client, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+columns+` FROM clients ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := []Client{}
	for rows.Next() {
		c, err := scan(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, c)
	}
	return list, rows.Err()
}

// RecordLogin notes that this login signed in to this product, keeping the
// latest email so the record can be found when that email is removed.
func (s *Store) RecordLogin(ctx context.Context, sub, clientID, email string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO user_client_links (sub, client_id, email) VALUES (?, ?, ?)
		ON CONFLICT (sub, client_id) DO UPDATE SET email = excluded.email, last_seen_at = CURRENT_TIMESTAMP`,
		sub, clientID, strings.ToLower(email))
	return err
}

// Logins lists recorded logins, optionally only those for one email.
func (s *Store) Logins(ctx context.Context, email string) ([]Login, error) {
	query := `
		SELECT l.sub, l.email, l.client_id, c.name, l.first_seen_at, l.last_seen_at
		FROM user_client_links l JOIN clients c ON c.id = l.client_id`
	args := []any{}
	if email != "" {
		query += ` WHERE l.email = ?`
		args = append(args, strings.ToLower(strings.TrimSpace(email)))
	}
	query += ` ORDER BY l.email, c.name`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := []Login{}
	for rows.Next() {
		var l Login
		if err := rows.Scan(&l.Sub, &l.Email, &l.ClientID, &l.ClientName, &l.FirstSeenAt, &l.LastSeenAt); err != nil {
			return nil, err
		}
		list = append(list, l)
	}
	return list, rows.Err()
}

// RevocationTargets lists every (login, product) pair recorded for email,
// i.e. every product that may still hold a session for that person.
func (s *Store) RevocationTargets(ctx context.Context, email string) ([]Target, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT l.sub, l.email, c.id, c.name, c.revoke_url, c.secret_hash
		FROM user_client_links l JOIN clients c ON c.id = l.client_id
		WHERE l.email = ?
		ORDER BY c.name, l.sub`, strings.ToLower(strings.TrimSpace(email)))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var targets []Target
	for rows.Next() {
		var t Target
		if err := rows.Scan(&t.Sub, &t.Email, &t.ClientID, &t.ClientName, &t.RevokeURL, &t.SigningKey); err != nil {
			return nil, err
		}
		targets = append(targets, t)
	}
	return targets, rows.Err()
}
