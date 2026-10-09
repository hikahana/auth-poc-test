package firebaseauth

import (
	"context"
	"fmt"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"google.golang.org/api/option"
)

// Identity is the subset of a verified Firebase ID token this platform cares about.
// Sub (the token's UID) is the stable identifier — email must never be used as the
// primary key since a user can change it.
type Identity struct {
	Sub           string
	Email         string
	EmailVerified bool
}

type Verifier struct {
	client *auth.Client
}

func NewVerifier(ctx context.Context, credentialsFile string) (*Verifier, error) {
	var opts []option.ClientOption
	if credentialsFile != "" {
		opts = append(opts, option.WithCredentialsFile(credentialsFile))
	}

	app, err := firebase.NewApp(ctx, nil, opts...)
	if err != nil {
		return nil, fmt.Errorf("init firebase app: %w", err)
	}

	client, err := app.Auth(ctx)
	if err != nil {
		return nil, fmt.Errorf("init firebase auth client: %w", err)
	}

	return &Verifier{client: client}, nil
}

// RevokeRefreshTokens stops the user's browsers from minting new ID tokens.
// ID tokens already issued stay valid until they expire (at most an hour).
func (v *Verifier) RevokeRefreshTokens(ctx context.Context, uid string) error {
	return v.client.RevokeRefreshTokens(ctx, uid)
}

// CustomTokenFor returns a custom token the browser exchanges for a Firebase
// session (signInWithCustomToken), creating the Firebase user on first use.
// Only call it for someone the whitelist has already let through: this is the
// only way Firebase users get created, since the Google and email/password
// providers are switched off in the Firebase console.
func (v *Verifier) CustomTokenFor(ctx context.Context, email string) (string, error) {
	user, err := v.client.GetUserByEmail(ctx, email)
	if err != nil && !auth.IsUserNotFound(err) {
		return "", fmt.Errorf("look up firebase user: %w", err)
	}

	// An unverified user was made by someone who never proved they own the
	// address (an email/password sign-up from before the providers were
	// switched off). verify never let it in anywhere, so nothing refers to its
	// UID; replace it rather than vouching for whoever set its password.
	if user != nil && !user.EmailVerified {
		if err := v.client.DeleteUser(ctx, user.UID); err != nil {
			return "", fmt.Errorf("delete unverified firebase user: %w", err)
		}
		user = nil
	}

	if user == nil {
		user, err = v.client.CreateUser(ctx, (&auth.UserToCreate{}).Email(email).EmailVerified(true))
		if err != nil {
			return "", fmt.Errorf("create firebase user: %w", err)
		}
	}

	token, err := v.client.CustomToken(ctx, user.UID)
	if err != nil {
		return "", fmt.Errorf("mint custom token: %w", err)
	}
	return token, nil
}

// Verify checks the ID token's signature, expiry, and issuer, and returns the
// caller's identity. It does not check the whitelist — that is a separate,
// application-level concern (see internal/whitelist).
func (v *Verifier) Verify(ctx context.Context, idToken string) (Identity, error) {
	token, err := v.client.VerifyIDToken(ctx, idToken)
	if err != nil {
		return Identity{}, fmt.Errorf("verify id token: %w", err)
	}

	email, _ := token.Claims["email"].(string)
	emailVerified, _ := token.Claims["email_verified"].(bool)

	return Identity{
		Sub:           token.UID,
		Email:         email,
		EmailVerified: emailVerified,
	}, nil
}
