package usecase

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/hikahana/auth-poc-test/examples/finansu-mock/authplatform"
	"github.com/hikahana/auth-poc-test/examples/finansu-mock/repository"
	"github.com/hikahana/auth-poc-test/examples/finansu-mock/store"
)

type fakeVerifier struct {
	result authplatform.Result
	err    error
}

func (f *fakeVerifier) Verify(context.Context, string) (authplatform.Result, error) {
	return f.result, f.err
}

type fixture struct {
	db       *sql.DB
	verifier *fakeVerifier
	mailAuth *MailAuthUseCase
	user     *UserUseCase
	firebase *FirebaseAuthUseCase
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	ur := repository.NewUserRepository(db)
	mr := repository.NewMailAuthRepository(db)
	sr := repository.NewSessionRepository(db)
	v := &fakeVerifier{}
	return &fixture{
		db:       db,
		verifier: v,
		mailAuth: NewMailAuthUseCase(mr, sr),
		user:     NewUserUseCase(ur, sr),
		firebase: NewFirebaseAuthUseCase(v, ur, mr, sr),
	}
}

// existingUser recreates FinanSu's sign-up: POST /users then POST /mail_auth/signup.
func (f *fixture) existingUser(t *testing.T, email string, roleID int) int {
	t.Helper()
	ctx := context.Background()
	u, err := f.user.Create(ctx, email, 1, roleID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.mailAuth.SignUp(ctx, email, "password", u.ID); err != nil {
		t.Fatal(err)
	}
	return u.ID
}

func (f *fixture) platformSays(status, sub, email string, emailVerified bool) {
	f.verifier.result = authplatform.Result{Status: status, Sub: sub, Email: email, EmailVerified: emailVerified}
	f.verifier.err = nil
}

func TestFirebaseSignInLinksExistingUserByVerifiedEmail(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	userID := f.existingUser(t, "Member@Example.com", 4)
	f.platformSays("allowed", "firebase-uid-1", "member@example.com", true)

	token, err := f.firebase.SignIn(ctx, "id-token")
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}

	current, err := f.user.GetCurrentUser(ctx, token.AccessToken)
	if err != nil {
		t.Fatalf("GetCurrentUser: %v", err)
	}
	if current.ID != userID || current.RoleID != 4 {
		t.Fatalf("got user %d role %d, want user %d role 4", current.ID, current.RoleID, userID)
	}
	if current.AuthPlatformUserID == nil || *current.AuthPlatformUserID != "firebase-uid-1" {
		t.Fatalf("auth_platform_user_id not linked: %v", current.AuthPlatformUserID)
	}
}

func TestFirebaseSignInFindsLinkedUserBySubAfterEmailChange(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	userID := f.existingUser(t, "member@example.com", 1)
	f.platformSays("allowed", "firebase-uid-1", "member@example.com", true)
	if _, err := f.firebase.SignIn(ctx, "id-token"); err != nil {
		t.Fatal(err)
	}

	f.platformSays("allowed", "firebase-uid-1", "renamed@example.com", true)
	token, err := f.firebase.SignIn(ctx, "id-token")
	if err != nil {
		t.Fatalf("SignIn after email change: %v", err)
	}
	current, _ := f.user.GetCurrentUser(ctx, token.AccessToken)
	if current.ID != userID {
		t.Fatalf("got user %d, want %d", current.ID, userID)
	}
}

func TestFirebaseSignInRejections(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*fixture, *testing.T)
		want    error
		wantAny bool
	}{
		{
			name:  "invalid token",
			setup: func(f *fixture, t *testing.T) { f.platformSays("invalid", "", "", false) },
			want:  ErrInvalidToken,
		},
		{
			name: "not on the whitelist",
			setup: func(f *fixture, t *testing.T) {
				f.existingUser(t, "member@example.com", 1)
				f.platformSays("not_whitelisted", "firebase-uid-1", "member@example.com", true)
			},
			want: ErrNotAllowed,
		},
		{
			name: "unverified email is never linked",
			setup: func(f *fixture, t *testing.T) {
				f.existingUser(t, "member@example.com", 1)
				f.platformSays("allowed", "firebase-uid-1", "member@example.com", false)
			},
			want: ErrEmailNotVerified,
		},
		{
			name: "account already linked to a different login",
			setup: func(f *fixture, t *testing.T) {
				f.existingUser(t, "member@example.com", 1)
				f.platformSays("allowed", "someone-else", "member@example.com", true)
				if _, err := f.firebase.SignIn(context.Background(), "id-token"); err != nil {
					t.Fatal(err)
				}
				f.platformSays("allowed", "firebase-uid-1", "member@example.com", true)
			},
			want: ErrAlreadyLinked,
		},
		{
			name: "soft-deleted user",
			setup: func(f *fixture, t *testing.T) {
				id := f.existingUser(t, "member@example.com", 1)
				if _, err := f.db.Exec(`UPDATE users SET is_deleted = true WHERE id = ?`, id); err != nil {
					t.Fatal(err)
				}
				f.platformSays("allowed", "firebase-uid-1", "member@example.com", true)
			},
			want: ErrNoAccount,
		},
		{
			name: "auth platform unreachable",
			setup: func(f *fixture, t *testing.T) {
				f.verifier.err = errors.New("connection refused")
			},
			wantAny: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			tt.setup(f, t)

			_, err := f.firebase.SignIn(context.Background(), "id-token")
			if tt.wantAny {
				if err == nil {
					t.Fatal("want error, got nil")
				}
				return
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
		})
	}
}

func TestFirebaseAndPasswordLoginShareFinanSusSingleSession(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.existingUser(t, "member@example.com", 1)

	passwordToken, err := f.mailAuth.SignIn(ctx, "member@example.com", "password")
	if err != nil {
		t.Fatalf("password SignIn: %v", err)
	}

	f.platformSays("allowed", "firebase-uid-1", "member@example.com", true)
	firebaseToken, err := f.firebase.SignIn(ctx, "id-token")
	if err != nil {
		t.Fatalf("firebase SignIn: %v", err)
	}

	if f.mailAuth.IsSignIn(ctx, passwordToken.AccessToken).IsSignIn {
		t.Fatal("password session should be replaced by the Firebase login")
	}
	if !f.mailAuth.IsSignIn(ctx, firebaseToken.AccessToken).IsSignIn {
		t.Fatal("Firebase session should be active")
	}
}

func TestFirebaseSignInAsksWhitelistedMemberWithoutAccountToRegister(t *testing.T) {
	f := newFixture(t)
	f.platformSays("allowed", "firebase-uid-1", "newcomer@example.com", true)

	_, err := f.firebase.SignIn(context.Background(), "id-token")

	var regErr *RegistrationRequiredError
	if !errors.As(err, &regErr) {
		t.Fatalf("got %v, want RegistrationRequiredError", err)
	}
	if regErr.Email != "newcomer@example.com" {
		t.Fatalf("email = %q, want newcomer@example.com", regErr.Email)
	}
}

func TestFirebaseSignUpCreatesUserRoleAccountFromTokenEmail(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.platformSays("allowed", "firebase-uid-1", "newcomer@example.com", true)

	token, err := f.firebase.SignUp(ctx, "id-token", "  Newcomer ", 3)
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}

	current, err := f.user.GetCurrentUser(ctx, token.AccessToken)
	if err != nil {
		t.Fatalf("GetCurrentUser: %v", err)
	}
	if current.Name != "Newcomer" || current.BureauID != 3 || current.RoleID != signUpRoleID {
		t.Fatalf("got %+v, want name Newcomer, bureau 3, role %d", current, signUpRoleID)
	}
	if current.AuthPlatformUserID == nil || *current.AuthPlatformUserID != "firebase-uid-1" {
		t.Fatalf("auth_platform_user_id not set: %v", current.AuthPlatformUserID)
	}

	// The account is usable from the next Google login onwards.
	if _, err := f.firebase.SignIn(ctx, "id-token"); err != nil {
		t.Fatalf("SignIn after SignUp: %v", err)
	}
	// And nobody can log in with the random password it was given.
	if _, err := f.mailAuth.SignIn(ctx, "newcomer@example.com", ""); err == nil {
		t.Fatal("empty password must not sign in")
	}
}

func TestFirebaseSignUpRejections(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*fixture, *testing.T)
		userName string
		bureauID int
		want     error
	}{
		{
			name:     "account already exists for the email",
			setup:    func(f *fixture, t *testing.T) { f.existingUser(t, "Member@Example.com", 1) },
			userName: "x", bureauID: 1,
			want: ErrAlreadyRegistered,
		},
		{
			name: "already signed up with this login",
			setup: func(f *fixture, t *testing.T) {
				if _, err := f.firebase.SignUp(context.Background(), "id-token", "first", 1); err != nil {
					t.Fatal(err)
				}
			},
			userName: "second", bureauID: 1,
			want: ErrAlreadyRegistered,
		},
		{
			name:     "missing name",
			userName: " ", bureauID: 1,
			want: ErrInvalidSignUp,
		},
		{
			name:     "missing bureau",
			userName: "x", bureauID: 0,
			want: ErrInvalidSignUp,
		},
		{
			name: "not on the whitelist",
			setup: func(f *fixture, t *testing.T) {
				f.platformSays("not_whitelisted", "firebase-uid-1", "member@example.com", true)
			},
			userName: "x", bureauID: 1,
			want: ErrNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			f.platformSays("allowed", "firebase-uid-1", "member@example.com", true)
			if tt.setup != nil {
				tt.setup(f, t)
			}

			_, err := f.firebase.SignUp(context.Background(), "id-token", tt.userName, tt.bureauID)
			if !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
		})
	}
}
