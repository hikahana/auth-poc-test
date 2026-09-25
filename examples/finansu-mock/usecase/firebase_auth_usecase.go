package usecase

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/hikahana/auth-poc-test/examples/finansu-mock/authplatform"
	"github.com/hikahana/auth-poc-test/examples/finansu-mock/domain"
	"github.com/hikahana/auth-poc-test/examples/finansu-mock/repository"
)

var (
	ErrInvalidToken     = errors.New("invalid id token")
	ErrNotApproved      = errors.New("login not approved")
	ErrEmailNotVerified = errors.New("email is not verified")
	ErrNoAccount        = errors.New("no FinanSu account for this login")
	ErrAlreadyLinked    = errors.New("this FinanSu account is already linked to another login")
)

type Verifier interface {
	Verify(ctx context.Context, idToken string) (authplatform.Result, error)
}

// FirebaseAuthUseCase signs a user in through the shared auth platform and
// hands back the same session access token as the password login, so the
// rest of FinanSu (current_user, the frontend's role checks) is unchanged.
type FirebaseAuthUseCase struct {
	verifier    Verifier
	userRep     *repository.UserRepository
	mailAuthRep *repository.MailAuthRepository
	sessionRep  *repository.SessionRepository
}

func NewFirebaseAuthUseCase(v Verifier, ur *repository.UserRepository, mr *repository.MailAuthRepository, sr *repository.SessionRepository) *FirebaseAuthUseCase {
	return &FirebaseAuthUseCase{verifier: v, userRep: ur, mailAuthRep: mr, sessionRep: sr}
}

func (u *FirebaseAuthUseCase) SignIn(c context.Context, idToken string) (domain.Token, error) {
	result, err := u.verifier.Verify(c, idToken)
	if err != nil {
		return domain.Token{}, err
	}
	switch result.Status {
	case authplatform.StatusApproved:
	case authplatform.StatusInvalid:
		return domain.Token{}, ErrInvalidToken
	default:
		return domain.Token{}, fmt.Errorf("%w (%s)", ErrNotApproved, result.Status)
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

// linkByEmail ties a first-time Firebase login to the FinanSu user whose
// mail_auth email matches. Only verified emails may be linked; otherwise
// anyone could claim an account by registering its address in Firebase.
func (u *FirebaseAuthUseCase) linkByEmail(c context.Context, result authplatform.Result) (domain.User, error) {
	if !result.EmailVerified {
		return domain.User{}, ErrEmailNotVerified
	}

	mailAuth, err := u.mailAuthRep.FindByEmail(c, result.Email)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.User{}, ErrNoAccount
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
