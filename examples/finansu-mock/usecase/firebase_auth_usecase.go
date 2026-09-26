package usecase

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/hikahana/auth-poc-test/examples/finansu-mock/authplatform"
	"github.com/hikahana/auth-poc-test/examples/finansu-mock/domain"
	"github.com/hikahana/auth-poc-test/examples/finansu-mock/repository"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidToken      = errors.New("invalid id token")
	ErrNotAllowed        = errors.New("login not allowed")
	ErrEmailNotVerified  = errors.New("email is not verified")
	ErrNoAccount         = errors.New("this FinanSu account cannot sign in")
	ErrAlreadyLinked     = errors.New("this FinanSu account is already linked to another login")
	ErrAlreadyRegistered = errors.New("a FinanSu account already exists for this login; sign in instead")
	ErrInvalidSignUp     = errors.New("name and bureau_id are required")
)

// RegistrationRequiredError means the login is whitelisted but has no FinanSu
// account yet; the frontend should open sign-up with Email fixed.
type RegistrationRequiredError struct {
	Email string
}

func (e *RegistrationRequiredError) Error() string {
	return "no FinanSu account for " + e.Email + "; registration required"
}

// signUpRoleID matches the role FinanSu's own SignUpView always sends
// (1: user). Higher roles are granted afterwards inside FinanSu.
const signUpRoleID = 1

type Verifier interface {
	Verify(ctx context.Context, idToken string) (authplatform.Result, error)
}

// FirebaseAuthUseCase signs a user in (or up) through the shared auth
// platform and hands back the same session access token as the password
// login, so the rest of FinanSu (current_user, the frontend's role checks) is
// unchanged.
type FirebaseAuthUseCase struct {
	verifier    Verifier
	userRep     *repository.UserRepository
	mailAuthRep *repository.MailAuthRepository
	sessionRep  *repository.SessionRepository
}

func NewFirebaseAuthUseCase(v Verifier, ur *repository.UserRepository, mr *repository.MailAuthRepository, sr *repository.SessionRepository) *FirebaseAuthUseCase {
	return &FirebaseAuthUseCase{verifier: v, userRep: ur, mailAuthRep: mr, sessionRep: sr}
}

func (u *FirebaseAuthUseCase) verifyAllowed(c context.Context, idToken string) (authplatform.Result, error) {
	result, err := u.verifier.Verify(c, idToken)
	if err != nil {
		return result, err
	}
	switch result.Status {
	case authplatform.StatusAllowed:
		return result, nil
	case authplatform.StatusInvalid:
		return result, ErrInvalidToken
	default:
		return result, fmt.Errorf("%w (%s)", ErrNotAllowed, result.Status)
	}
}

func (u *FirebaseAuthUseCase) SignIn(c context.Context, idToken string) (domain.Token, error) {
	result, err := u.verifyAllowed(c, idToken)
	if err != nil {
		return domain.Token{}, err
	}

	user, err := u.userRep.FindByAuthPlatformUserID(c, result.Sub)
	if errors.Is(err, sql.ErrNoRows) {
		user, err = u.linkByEmail(c, result)
	}
	if err != nil {
		return domain.Token{}, err
	}
	if user.IsDeleted {
		return domain.Token{}, ErrNoAccount
	}

	// session.auth_id references mail_auth, so the Firebase login reuses the
	// user's existing mail_auth row rather than adding a new auth table.
	mailAuth, err := u.mailAuthRep.FindByUserID(c, user.ID)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Token{}, ErrNoAccount
	}
	if err != nil {
		return domain.Token{}, err
	}

	return startSession(c, u.sessionRep, mailAuth.ID, user.ID)
}

// SignUp registers a whitelisted member who has no FinanSu account yet. The
// email comes from the verified ID token, never from the form, so the fixed
// email field on the sign-up screen cannot be tampered with.
func (u *FirebaseAuthUseCase) SignUp(c context.Context, idToken, name string, bureauID int) (domain.Token, error) {
	name = strings.TrimSpace(name)
	if name == "" || bureauID <= 0 {
		return domain.Token{}, ErrInvalidSignUp
	}

	result, err := u.verifyAllowed(c, idToken)
	if err != nil {
		return domain.Token{}, err
	}

	if _, err := u.userRep.FindByAuthPlatformUserID(c, result.Sub); err == nil {
		return domain.Token{}, ErrAlreadyRegistered
	} else if !errors.Is(err, sql.ErrNoRows) {
		return domain.Token{}, err
	}
	if _, err := u.mailAuthRep.FindByEmail(c, result.Email); err == nil {
		return domain.Token{}, ErrAlreadyRegistered
	} else if !errors.Is(err, sql.ErrNoRows) {
		return domain.Token{}, err
	}

	// mail_auth.password is NOT NULL, but Google-only members never use a
	// password; hash an unguessable random one.
	hashed, err := randomPasswordHash()
	if err != nil {
		return domain.Token{}, err
	}

	userID, mailAuthID, err := u.userRep.RegisterFirebaseUser(c, name, bureauID, signUpRoleID, result.Sub, result.Email, hashed)
	if err != nil {
		return domain.Token{}, err
	}

	return startSession(c, u.sessionRep, mailAuthID, userID)
}

// linkByEmail ties a first-time Firebase login to the FinanSu user whose
// mail_auth email matches. Only verified emails may be linked; otherwise
// anyone could claim an account by registering its address in Firebase.
func (u *FirebaseAuthUseCase) linkByEmail(c context.Context, result authplatform.Result) (domain.User, error) {
	if !result.EmailVerified {
		return domain.User{}, ErrEmailNotVerified
	}

	mailAuth, err := u.mailAuthRep.FindByEmail(c, result.Email)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.User{}, &RegistrationRequiredError{Email: result.Email}
	}
	if err != nil {
		return domain.User{}, err
	}

	linked, err := u.userRep.LinkAuthPlatformUserID(c, mailAuth.UserID, result.Sub)
	if err != nil {
		return domain.User{}, err
	}
	if !linked {
		return domain.User{}, ErrAlreadyLinked
	}
	return u.userRep.Find(c, mailAuth.UserID)
}

func randomPasswordHash() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(base64.StdEncoding.EncodeToString(b)), 10)
	return string(hashed), err
}
