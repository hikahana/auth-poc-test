// Package repository mirrors FinanSu's user / mail_auth / session repositories,
// using placeholders instead of the real code's string-concatenated SQL.
package repository

import (
	"context"
	"database/sql"

	"github.com/hikahana/auth-poc-test/examples/finansu-mock/domain"
)

type UserRepository struct{ db *sql.DB }

func NewUserRepository(db *sql.DB) *UserRepository { return &UserRepository{db} }

const userColumns = `id, name, bureau_id, role_id, is_deleted, auth_platform_user_id, created_at, updated_at`

func scanUser(row *sql.Row) (domain.User, error) {
	var u domain.User
	var authPlatformUserID sql.NullString
	err := row.Scan(&u.ID, &u.Name, &u.BureauID, &u.RoleID, &u.IsDeleted, &authPlatformUserID, &u.CreatedAt, &u.UpdatedAt)
	if authPlatformUserID.Valid {
		u.AuthPlatformUserID = &authPlatformUserID.String
	}
	return u, err
}

func (r *UserRepository) Create(c context.Context, name string, bureauID, roleID int) (int64, error) {
	res, err := r.db.ExecContext(c, `INSERT INTO users (name, bureau_id, role_id) VALUES (?, ?, ?)`, name, bureauID, roleID)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (r *UserRepository) Find(c context.Context, id int) (domain.User, error) {
	return scanUser(r.db.QueryRowContext(c, `SELECT `+userColumns+` FROM users WHERE id = ?`, id))
}

func (r *UserRepository) FindByAuthPlatformUserID(c context.Context, sub string) (domain.User, error) {
	return scanUser(r.db.QueryRowContext(c, `SELECT `+userColumns+` FROM users WHERE auth_platform_user_id = ?`, sub))
}

// LinkAuthPlatformUserID sets the link only if the user has none yet, so two
// concurrent first logins cannot both claim the same FinanSu account.
func (r *UserRepository) LinkAuthPlatformUserID(c context.Context, userID int, sub string) (bool, error) {
	res, err := r.db.ExecContext(c,
		`UPDATE users SET auth_platform_user_id = ? WHERE id = ? AND auth_platform_user_id IS NULL`, sub, userID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

type MailAuthRepository struct{ db *sql.DB }

func NewMailAuthRepository(db *sql.DB) *MailAuthRepository { return &MailAuthRepository{db} }

func scanMailAuth(row *sql.Row) (domain.MailAuth, error) {
	var m domain.MailAuth
	err := row.Scan(&m.ID, &m.Email, &m.Password, &m.UserID)
	return m, err
}

func (r *MailAuthRepository) Create(c context.Context, email, hashedPassword string, userID int) (int64, error) {
	res, err := r.db.ExecContext(c, `INSERT INTO mail_auth (email, password, user_id) VALUES (?, ?, ?)`, email, hashedPassword, userID)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (r *MailAuthRepository) FindByEmail(c context.Context, email string) (domain.MailAuth, error) {
	return scanMailAuth(r.db.QueryRowContext(c,
		`SELECT id, email, password, user_id FROM mail_auth WHERE lower(email) = lower(?)`, email))
}

func (r *MailAuthRepository) FindByUserID(c context.Context, userID int) (domain.MailAuth, error) {
	return scanMailAuth(r.db.QueryRowContext(c,
		`SELECT id, email, password, user_id FROM mail_auth WHERE user_id = ? ORDER BY id LIMIT 1`, userID))
}

type SessionRepository struct{ db *sql.DB }

func NewSessionRepository(db *sql.DB) *SessionRepository { return &SessionRepository{db} }

func (r *SessionRepository) Create(c context.Context, authID, userID int, accessToken string) error {
	_, err := r.db.ExecContext(c, `INSERT INTO session (auth_id, user_id, access_token) VALUES (?, ?, ?)`, authID, userID, accessToken)
	return err
}

func (r *SessionRepository) Destroy(c context.Context, accessToken string) error {
	_, err := r.db.ExecContext(c, `DELETE FROM session WHERE access_token = ?`, accessToken)
	return err
}

func (r *SessionRepository) DestroyByUserID(c context.Context, userID int) error {
	_, err := r.db.ExecContext(c, `DELETE FROM session WHERE user_id = ?`, userID)
	return err
}

func (r *SessionRepository) FindByAccessToken(c context.Context, accessToken string) (domain.Session, error) {
	var s domain.Session
	err := r.db.QueryRowContext(c,
		`SELECT id, auth_id, user_id, access_token FROM session WHERE access_token = ?`, accessToken).
		Scan(&s.ID, &s.AuthID, &s.UserID, &s.AccessToken)
	return s, err
}
