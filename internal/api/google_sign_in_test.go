package api

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"testing"

	"github.com/hikahana/auth-poc-test/internal/whitelist"
)

func (e *testEnv) googleSignIn(t *testing.T, credential string) (int, map[string]any) {
	t.Helper()
	return e.as(t, "", "POST", "/v1/auth/google", `{"credential":"`+credential+`"}`)
}

func TestGoogleSignInOnlyCreatesFirebaseUsersForPeopleItLetsIn(t *testing.T) {
	e := newTestEnv(t)
	e.as(t, seededAdmin, "POST", "/v1/admin/whitelist", `{"email":"23.retired.nutfes@gmail.com","role":"member"}`)
	e.as(t, seededAdmin, "POST", "/v1/admin/whitelist/23.retired.nutfes@gmail.com/disable", "")

	tests := []struct {
		credential string
		wantCode   int
		wantStatus string
	}{
		{member, http.StatusOK, StatusAllowed},
		{"stranger@gmail.com", http.StatusForbidden, StatusNotNutfesEmail},
		{"unverified:" + member, http.StatusForbidden, StatusEmailUnverified},
		{"23.retired.nutfes@gmail.com", http.StatusForbidden, StatusDisabled},
		{"bad", http.StatusUnauthorized, ""},
	}
	for _, tt := range tests {
		code, body := e.googleSignIn(t, tt.credential)
		status, _ := body["status"].(string)
		if code != tt.wantCode || status != tt.wantStatus {
			t.Errorf("google sign-in(%s) = %d %q, want %d %q", tt.credential, code, status, tt.wantCode, tt.wantStatus)
		}
		if token, _ := body["custom_token"].(string); (token != "") != (tt.wantCode == http.StatusOK) {
			t.Errorf("google sign-in(%s): custom_token = %q", tt.credential, token)
		}
	}

	if !slices.Equal(e.fb.created, []string{member}) {
		t.Fatalf("firebase users should only be made for allowed people, got %v", e.fb.created)
	}
	entry, err := e.wl.Lookup(context.Background(), member)
	if err != nil || entry.AddedBy != whitelist.AddedByAutoRegistration {
		t.Fatalf("first google sign-in should auto-register a member, got %+v, %v", entry, err)
	}
	if _, err := e.wl.Lookup(context.Background(), "stranger@gmail.com"); !errors.Is(err, whitelist.ErrNotFound) {
		t.Fatalf("a non-NUTFes address was registered: %v", err)
	}
}

func TestGoogleSignInRequiresACredential(t *testing.T) {
	e := newTestEnv(t)
	if code, _ := e.as(t, "", "POST", "/v1/auth/google", `{}`); code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", code)
	}
}
