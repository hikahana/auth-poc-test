package usecase

import (
	"context"
	"testing"
)

func TestRevokeSessionsEndsTheLinkedUsersSessionOnly(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.existingUser(t, "member@example.com", 1)
	f.existingUser(t, "other@example.com", 1)

	f.platformSays("allowed", "uid-member", "member@example.com", true)
	memberToken, err := f.firebase.SignIn(ctx, "id-token")
	if err != nil {
		t.Fatal(err)
	}
	otherToken, err := f.mailAuth.SignIn(ctx, "other@example.com", "password")
	if err != nil {
		t.Fatal(err)
	}

	if err := f.firebase.RevokeSessions(ctx, "uid-member"); err != nil {
		t.Fatalf("RevokeSessions: %v", err)
	}
	if f.mailAuth.IsSignIn(ctx, memberToken.AccessToken).IsSignIn {
		t.Error("the revoked user is still signed in")
	}
	if !f.mailAuth.IsSignIn(ctx, otherToken.AccessToken).IsSignIn {
		t.Error("a different user lost their session")
	}

	if err := f.firebase.RevokeSessions(ctx, "uid-unknown"); err != nil {
		t.Errorf("unknown sub should be a no-op, got %v", err)
	}
}
