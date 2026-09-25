// Package domain mirrors the auth-related structs in FinanSu api/internals/domain.
package domain

import "time"

type User struct {
	ID                 int       `json:"id"`
	Name               string    `json:"name"`
	BureauID           int       `json:"bureauID"`
	RoleID             int       `json:"roleID"`
	IsDeleted          bool      `json:"isDeleted"`
	AuthPlatformUserID *string   `json:"authPlatformUserID"`
	CreatedAt          time.Time `json:"createdAt"`
	UpdatedAt          time.Time `json:"updatedAt"`
}

type MailAuth struct {
	ID       int
	Email    string
	Password string
	UserID   int
}

type Session struct {
	ID          int
	AuthID      int
	UserID      int
	AccessToken string
}

type Token struct {
	AccessToken string `json:"accessToken"`
}

type IsSignIn struct {
	IsSignIn bool `json:"isSignIn"`
}
