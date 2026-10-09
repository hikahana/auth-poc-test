// Package googleauth verifies the Google ID tokens (Google Identity Services
// "credential") a browser gets from signing in with Google directly, before
// Firebase is involved. This is what lets the platform refuse someone without
// a Firebase user ever being created for them.
package googleauth

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/api/idtoken"
)

// Identity is the subset of a verified Google ID token the whitelist needs.
type Identity struct {
	Email         string
	EmailVerified bool
}

type Verifier struct {
	clientID string
}

// NewVerifier requires the OAuth client ID the sign-in button uses: the
// token's audience is checked against it, and without that check a token
// minted for any other site would be accepted.
func NewVerifier(clientID string) (*Verifier, error) {
	if clientID == "" {
		return nil, errors.New("GOOGLE_OAUTH_CLIENT_ID is required")
	}
	return &Verifier{clientID: clientID}, nil
}

// Verify checks the token's signature, expiry, audience, and issuer.
func (v *Verifier) Verify(ctx context.Context, credential string) (Identity, error) {
	payload, err := idtoken.Validate(ctx, credential, v.clientID)
	if err != nil {
		return Identity{}, fmt.Errorf("verify google id token: %w", err)
	}
	// idtoken.Validate checks the signature against Google's keys but not the issuer.
	if payload.Issuer != "accounts.google.com" && payload.Issuer != "https://accounts.google.com" {
		return Identity{}, fmt.Errorf("verify google id token: unexpected issuer %q", payload.Issuer)
	}

	email, _ := payload.Claims["email"].(string)
	emailVerified, _ := payload.Claims["email_verified"].(bool)
	return Identity{Email: email, EmailVerified: emailVerified}, nil
}
