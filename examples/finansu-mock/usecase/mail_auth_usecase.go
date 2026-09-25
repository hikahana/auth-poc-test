// Package usecase mirrors FinanSu api/internals/usecase for authentication.
package usecase

import (
	"context"
	"crypto/rand"
	"errors"

	"github.com/hikahana/auth-poc-test/examples/finansu-mock/domain"
	"github.com/hikahana/auth-poc-test/examples/finansu-mock/repository"
	"golang.org/x/crypto/bcrypt"
)

// MailAuthUseCase follows FinanSu's mail_auth_usecase.go: a sign-in replaces
// the user's session with a new random access token.
type MailAuthUseCase struct {
	mailAuthRep *repository.MailAuthRepository
	sessionRep  *repository.SessionRepository
}

func NewMailAuthUseCase(m *repository.MailAuthRepository, s *repository.SessionRepository) *MailAuthUseCase {
	return &MailAuthUseCase{mailAuthRep: m, sessionRep: s}
}

func (u *MailAuthUseCase) SignUp(c context.Context, email, password string, userID int) (domain.Token, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		return domain.Token{}, err
	}
	mailAuthID, err := u.mailAuthRep.Create(c, email, string(hashed), userID)
	if err != nil {
		return domain.Token{}, err
	}
	return startSession(c, u.sessionRep, int(mailAuthID), userID)
}

func (u *MailAuthUseCase) SignIn(c context.Context, email, password string) (domain.Token, error) {
	mailAuth, err := u.mailAuthRep.FindByEmail(c, email)
	if err != nil {
		return domain.Token{}, errors.New("メールアドレスが存在しません")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(mailAuth.Password), []byte(password)); err != nil {
		return domain.Token{}, err
	}
	return startSession(c, u.sessionRep, mailAuth.ID, mailAuth.UserID)
}

func (u *MailAuthUseCase) SignOut(c context.Context, accessToken string) error {
	return u.sessionRep.Destroy(c, accessToken)
}

func (u *MailAuthUseCase) IsSignIn(c context.Context, accessToken string) domain.IsSignIn {
	_, err := u.sessionRep.FindByAccessToken(c, accessToken)
	return domain.IsSignIn{IsSignIn: err == nil}
}

// startSession is the tail shared by every sign-in path, password or Firebase:
// FinanSu keeps a single session per user, so older tokens are revoked.
func startSession(c context.Context, sessionRep *repository.SessionRepository, authID, userID int) (domain.Token, error) {
	if err := sessionRep.DestroyByUserID(c, userID); err != nil {
		return domain.Token{}, err
	}
	accessToken, err := makeRandomStr(10)
	if err != nil {
		return domain.Token{}, err
	}
	if err := sessionRep.Create(c, authID, userID, accessToken); err != nil {
		return domain.Token{}, err
	}
	return domain.Token{AccessToken: accessToken}, nil
}

// makeRandomStr is FinanSu's _makeRandomStr.
func makeRandomStr(digit uint32) (string, error) {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	b := make([]byte, digit)
	if _, err := rand.Read(b); err != nil {
		return "", errors.New("unexpected error...")
	}

	var result string
	for _, v := range b {
		result += string(letters[int(v)%len(letters)])
	}
	return result, nil
}

type UserUseCase struct {
	userRep    *repository.UserRepository
	sessionRep *repository.SessionRepository
}

func NewUserUseCase(ur *repository.UserRepository, sr *repository.SessionRepository) *UserUseCase {
	return &UserUseCase{userRep: ur, sessionRep: sr}
}

func (u *UserUseCase) Create(c context.Context, name string, bureauID, roleID int) (domain.User, error) {
	id, err := u.userRep.Create(c, name, bureauID, roleID)
	if err != nil {
		return domain.User{}, err
	}
	return u.userRep.Find(c, int(id))
}

func (u *UserUseCase) GetCurrentUser(c context.Context, accessToken string) (domain.User, error) {
	session, err := u.sessionRep.FindByAccessToken(c, accessToken)
	if err != nil {
		return domain.User{}, err
	}
	return u.userRep.Find(c, session.UserID)
}
