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

const adminEmail = "admin@example.com"

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	wl, err := whitelist.Open(filepath.Join(t.TempDir(), "wl.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { wl.Close() })

	s := NewServer(fakeVerifier{}, wl, []string{adminEmail}, "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := httptest.NewServer(s.Routes())
	t.Cleanup(srv.Close)
	return srv
}

// doAs sends the request with a Google login (fake ID token) for `as`, or with
// no login when `as` is empty.
func doAs(t *testing.T, srv *httptest.Server, as, method, path, body string) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if as != "" {
		req.Header.Set("Authorization", "Bearer "+as)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, b
}

func do(t *testing.T, srv *httptest.Server, method, path, body string, admin bool) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if admin {
		req.Header.Set("Authorization", "Bearer "+adminEmail)
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

	code, body := do(t, srv, "POST", "/v1/admin/whitelist", `{"email":"member@example.com"}`, true)
	if code != http.StatusCreated {
		t.Fatalf("add: got %d", code)
	}
	if body["added_by"] != adminEmail {
		t.Errorf("added_by = %v, want the signed-in admin %s", body["added_by"], adminEmail)
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

	_, raw := doAs(t, srv, adminEmail, "GET", "/v1/admin/whitelist", "")
	var entries []whitelist.Entry
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("want empty whitelist, got %+v", entries)
	}
}

func TestRemovingFromWhitelistRevokesAccess(t *testing.T) {
	srv := newTestServer(t)
	do(t, srv, "POST", "/v1/admin/whitelist", `{"email":"member@example.com"}`, true)

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

func TestAdminRoutesRequireAnAdministratorsGoogleLogin(t *testing.T) {
	srv := newTestServer(t)

	callers := []struct {
		name string
		as   string
		want int
	}{
		{"not signed in", "", http.StatusUnauthorized},
		{"invalid token", "bad", http.StatusUnauthorized},
		{"signed in but not an admin", "member@example.com", http.StatusForbidden},
		{"admin email but not verified", "unverified:" + adminEmail, http.StatusForbidden},
	}
	routes := []struct{ method, path, body string }{
		{"GET", "/v1/admin/whitelist", ""},
		{"POST", "/v1/admin/whitelist", `{"email":"x@example.com"}`},
		{"DELETE", "/v1/admin/whitelist/x@example.com", ""},
	}

	for _, c := range callers {
		for _, r := range routes {
			if code, _ := doAs(t, srv, c.as, r.method, r.path, r.body); code != c.want {
				t.Errorf("%s: %s %s got %d, want %d", c.name, r.method, r.path, code, c.want)
			}
		}
	}

	if code, _ := doAs(t, srv, "ADMIN@Example.com", "GET", "/v1/admin/whitelist", ""); code != http.StatusOK {
		t.Errorf("admin email should match case-insensitively, got %d", code)
	}
}
