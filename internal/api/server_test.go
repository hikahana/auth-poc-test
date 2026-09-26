package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hikahana/auth-poc-test/internal/firebaseauth"
	"github.com/hikahana/auth-poc-test/internal/whitelist"
)

// fakeVerifier treats the ID token string itself as the email, so each test
// request can pick its identity. The "unverified:" prefix and "bad" token
// cover the other verifier outcomes.
type fakeVerifier struct{}

func (fakeVerifier) Verify(_ context.Context, idToken string) (firebaseauth.Identity, error) {
	if idToken == "bad" {
		return firebaseauth.Identity{}, errors.New("bad token")
	}
	if email, ok := strings.CutPrefix(idToken, "unverified:"); ok {
		return firebaseauth.Identity{Sub: "uid-" + email, Email: email, EmailVerified: false}, nil
	}
	return firebaseauth.Identity{Sub: "uid-" + idToken, Email: idToken, EmailVerified: true}, nil
}

const adminKey = "test-admin-key"

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	wl, err := whitelist.Open(filepath.Join(t.TempDir(), "wl.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { wl.Close() })

	s := NewServer(fakeVerifier{}, wl, adminKey, "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := httptest.NewServer(s.Routes())
	t.Cleanup(srv.Close)
	return srv
}

func do(t *testing.T, srv *httptest.Server, method, path, body string, admin bool) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if admin {
		req.Header.Set("X-Admin-Key", adminKey)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func verify(t *testing.T, srv *httptest.Server, token string) (int, string) {
	t.Helper()
	code, body := do(t, srv, "POST", "/v1/auth/verify", `{"id_token":"`+token+`"}`, false)
	status, _ := body["status"].(string)
	return code, status
}

func TestVerifyAllowsOnlyPreRegisteredVerifiedEmails(t *testing.T) {
	srv := newTestServer(t)

	if code, _ := do(t, srv, "POST", "/v1/admin/whitelist", `{"email":"member@example.com","added_by":"admin"}`, true); code != http.StatusCreated {
		t.Fatalf("add: got %d", code)
	}

	tests := []struct {
		token      string
		wantCode   int
		wantStatus string
	}{
		{"member@example.com", http.StatusOK, StatusAllowed},
		{"stranger@example.com", http.StatusForbidden, StatusNotWhitelisted},
		{"unverified:member@example.com", http.StatusForbidden, StatusEmailUnverified},
		{"bad", http.StatusUnauthorized, ""},
	}
	for _, tt := range tests {
		code, status := verify(t, srv, tt.token)
		if code != tt.wantCode || status != tt.wantStatus {
			t.Errorf("verify(%s) = %d %q, want %d %q", tt.token, code, status, tt.wantCode, tt.wantStatus)
		}
	}
}

func TestVerifyingAStrangerDoesNotAddThemToTheWhitelist(t *testing.T) {
	srv := newTestServer(t)

	verify(t, srv, "stranger@example.com")

	req, _ := http.NewRequest("GET", srv.URL+"/v1/admin/whitelist", nil)
	req.Header.Set("X-Admin-Key", adminKey)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var entries []whitelist.Entry
	if err := json.NewDecoder(res.Body).Decode(&entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("want empty whitelist, got %+v", entries)
	}
}

func TestRemovingFromWhitelistRevokesAccess(t *testing.T) {
	srv := newTestServer(t)
	do(t, srv, "POST", "/v1/admin/whitelist", `{"email":"member@example.com","added_by":"admin"}`, true)

	if code, _ := do(t, srv, "DELETE", "/v1/admin/whitelist/member@example.com", "", true); code != http.StatusNoContent {
		t.Fatalf("delete: got %d", code)
	}
	if code, status := verify(t, srv, "member@example.com"); code != http.StatusForbidden || status != StatusNotWhitelisted {
		t.Fatalf("after delete: got %d %q", code, status)
	}
	if code, _ := do(t, srv, "DELETE", "/v1/admin/whitelist/member@example.com", "", true); code != http.StatusNotFound {
		t.Fatalf("second delete: got %d, want 404", code)
	}
}

func TestAdminRoutesRequireTheAdminKey(t *testing.T) {
	srv := newTestServer(t)

	for _, r := range []struct{ method, path, body string }{
		{"GET", "/v1/admin/whitelist", ""},
		{"POST", "/v1/admin/whitelist", `{"email":"x@example.com","added_by":"me"}`},
		{"DELETE", "/v1/admin/whitelist/x@example.com", ""},
	} {
		if code, _ := do(t, srv, r.method, r.path, r.body, false); code != http.StatusUnauthorized {
			t.Errorf("%s %s without key: got %d, want 401", r.method, r.path, code)
		}
	}
}
