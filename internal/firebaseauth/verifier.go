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
