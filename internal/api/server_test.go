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

	"github.com/hikahana/auth-poc-test/internal/clients"
	"github.com/hikahana/auth-poc-test/internal/firebaseauth"
	"github.com/hikahana/auth-poc-test/internal/store"
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

const seededAdmin = "admin@example.com"

type testEnv struct {
	srv *httptest.Server
	wl  *whitelist.Store
	cl  *clients.Store
	// credentials of a registered product ("GM2") used by verify
	clientID, clientSecret string
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "platform.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	ctx := context.Background()
	wl := whitelist.New(db)
	if _, err := wl.Add(ctx, seededAdmin, whitelist.RoleAdmin, "seed"); err != nil {
		t.Fatal(err)
	}
	cl := clients.New(db)
	gm2, secret, err := cl.Create(ctx, "GM2")
	if err != nil {
		t.Fatal(err)
	}

	s := NewServer(Deps{
		Verifier:  fakeVerifier{},
		Whitelist: wl,
		Clients:   cl,
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	srv := httptest.NewServer(s.Routes())
	t.Cleanup(srv.Close)
	return &testEnv{srv: srv, wl: wl, cl: cl, clientID: gm2.ID, clientSecret: secret}
}

// as sends a request signed in (fake ID token) as `who`, or anonymously when
// `who` is empty, and decodes a JSON object response.
func (e *testEnv) as(t *testing.T, who, method, path, body string) (int, map[string]any) {
	t.Helper()
	code, raw := e.raw(t, who, method, path, body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return code, out
}

func (e *testEnv) raw(t *testing.T, who, method, path, body string) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, e.srv.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if who != "" {
		req.Header.Set("Authorization", "Bearer "+who)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, b
}

// verifyWith calls verify as a product with the given client credentials.
func (e *testEnv) verifyWith(t *testing.T, clientID, clientSecret, token string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", e.srv.URL+"/v1/auth/verify", strings.NewReader(`{"id_token":"`+token+`"}`))
	req.Header.Set("Content-Type", "application/json")
	if clientID != "" {
		req.SetBasicAuth(clientID, clientSecret)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(res.Body).Decode(&body)
	status, _ := body["status"].(string)
	return res.StatusCode, status
}

func (e *testEnv) verify(t *testing.T, token string) (int, string) {
	t.Helper()
	return e.verifyWith(t, e.clientID, e.clientSecret, token)
}

func TestVerifyAllowsOnlyRegisteredVerifiedEmails(t *testing.T) {
	e := newTestEnv(t)

	code, body := e.as(t, seededAdmin, "POST", "/v1/admin/whitelist", `{"email":"member@example.com"}`)
	if code != http.StatusCreated {
		t.Fatalf("add: got %d", code)
	}
	if body["added_by"] != seededAdmin || body["role"] != "member" {
		t.Errorf("added entry = %v, want role member added by %s", body, seededAdmin)
	}

	tests := []struct {
		token      string
		wantCode   int
		wantStatus string
	}{
		{"member@example.com", http.StatusOK, StatusAllowed},
		{seededAdmin, http.StatusOK, StatusAllowed},
		{"stranger@example.com", http.StatusForbidden, StatusNotWhitelisted},
		{"unverified:member@example.com", http.StatusForbidden, StatusEmailUnverified},
		{"bad", http.StatusUnauthorized, ""},
	}
	for _, tt := range tests {
		code, status := e.verify(t, tt.token)
		if code != tt.wantCode || status != tt.wantStatus {
			t.Errorf("verify(%s) = %d %q, want %d %q", tt.token, code, status, tt.wantCode, tt.wantStatus)
		}
	}
}

func TestVerifyingAStrangerDoesNotAddThemToTheWhitelist(t *testing.T) {
	e := newTestEnv(t)

	e.verify(t, "stranger@example.com")

	if _, err := e.wl.Lookup(context.Background(), "stranger@example.com"); !errors.Is(err, whitelist.ErrNotFound) {
		t.Fatalf("stranger was registered: %v", err)
	}
}

func TestRemovingFromWhitelistRevokesAccess(t *testing.T) {
	e := newTestEnv(t)
	e.as(t, seededAdmin, "POST", "/v1/admin/whitelist", `{"email":"member@example.com"}`)

	if code, _ := e.as(t, seededAdmin, "DELETE", "/v1/admin/whitelist/member@example.com", ""); code != http.StatusNoContent {
		t.Fatalf("delete: got %d", code)
	}
	if code, status := e.verify(t, "member@example.com"); code != http.StatusForbidden || status != StatusNotWhitelisted {
		t.Fatalf("after delete: got %d %q", code, status)
	}
	if code, _ := e.as(t, seededAdmin, "DELETE", "/v1/admin/whitelist/member@example.com", ""); code != http.StatusNotFound {
		t.Fatalf("second delete: got %d, want 404", code)
	}
}

func TestAdminRoutesRequireTheAdminRole(t *testing.T) {
	e := newTestEnv(t)
	e.as(t, seededAdmin, "POST", "/v1/admin/whitelist", `{"email":"member@example.com"}`)

	callers := []struct {
		name string
		who  string
		want int
	}{
		{"not signed in", "", http.StatusUnauthorized},
		{"invalid token", "bad", http.StatusUnauthorized},
		{"whitelisted member", "member@example.com", http.StatusForbidden},
		{"not on the whitelist", "stranger@example.com", http.StatusForbidden},
		{"admin email but not verified", "unverified:" + seededAdmin, http.StatusForbidden},
	}
	routes := []struct{ method, path, body string }{
		{"GET", "/v1/admin/whitelist", ""},
		{"POST", "/v1/admin/whitelist", `{"email":"x@example.com"}`},
		{"PATCH", "/v1/admin/whitelist/member@example.com", `{"role":"admin"}`},
		{"DELETE", "/v1/admin/whitelist/member@example.com", ""},
		{"GET", "/v1/admin/clients", ""},
		{"POST", "/v1/admin/clients", `{"name":"X"}`},
		{"PATCH", "/v1/admin/clients/" + e.clientID, `{"is_active":false}`},
		{"POST", "/v1/admin/clients/" + e.clientID + "/secret", ""},
		{"GET", "/v1/admin/logins", ""},
	}

	for _, c := range callers {
		for _, r := range routes {
			if code, _ := e.raw(t, c.who, r.method, r.path, r.body); code != c.want {
				t.Errorf("%s: %s %s got %d, want %d", c.name, r.method, r.path, code, c.want)
			}
		}
	}

	if code, _ := e.raw(t, "ADMIN@Example.com", "GET", "/v1/admin/whitelist", ""); code != http.StatusOK {
		t.Errorf("admin email should match case-insensitively, got %d", code)
	}
}

func TestAdminsCanPromoteAndTheNewAdminCanManage(t *testing.T) {
	e := newTestEnv(t)
	e.as(t, seededAdmin, "POST", "/v1/admin/whitelist", `{"email":"member@example.com"}`)

	code, body := e.as(t, seededAdmin, "PATCH", "/v1/admin/whitelist/member@example.com", `{"role":"admin"}`)
	if code != http.StatusOK || body["role"] != "admin" {
		t.Fatalf("promote: %d %v", code, body)
	}
	if code, _ := e.raw(t, "member@example.com", "GET", "/v1/admin/whitelist", ""); code != http.StatusOK {
		t.Fatalf("promoted admin: got %d", code)
	}

	code, body = e.as(t, "member@example.com", "POST", "/v1/admin/whitelist", `{"email":"second-admin@example.com","role":"admin"}`)
	if code != http.StatusCreated || body["role"] != "admin" {
		t.Fatalf("add as admin: %d %v", code, body)
	}
}

func TestTheLastAdminIsProtected(t *testing.T) {
	e := newTestEnv(t)

	if code, _ := e.as(t, seededAdmin, "DELETE", "/v1/admin/whitelist/"+seededAdmin, ""); code != http.StatusConflict {
		t.Errorf("delete last admin: got %d, want 409", code)
	}
	if code, _ := e.as(t, seededAdmin, "PATCH", "/v1/admin/whitelist/"+seededAdmin, `{"role":"member"}`); code != http.StatusConflict {
		t.Errorf("demote last admin: got %d, want 409", code)
	}
}

func TestAdminInputValidation(t *testing.T) {
	e := newTestEnv(t)

	for _, r := range []struct {
		method, path, body string
		want               int
	}{
		{"POST", "/v1/admin/whitelist", `{"email":"no-at-sign"}`, http.StatusBadRequest},
		{"POST", "/v1/admin/whitelist", `{"email":"x@example.com","role":"owner"}`, http.StatusBadRequest},
		{"PATCH", "/v1/admin/whitelist/" + seededAdmin, `{"role":"owner"}`, http.StatusBadRequest},
		{"PATCH", "/v1/admin/whitelist/ghost@example.com", `{"role":"admin"}`, http.StatusNotFound},
	} {
		if code, _ := e.raw(t, seededAdmin, r.method, r.path, r.body); code != r.want {
			t.Errorf("%s %s %s: got %d, want %d", r.method, r.path, r.body, code, r.want)
		}
	}
}
