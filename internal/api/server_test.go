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
	"time"

	"github.com/hikahana/auth-poc-test/internal/clients"
	"github.com/hikahana/auth-poc-test/internal/firebaseauth"
	"github.com/hikahana/auth-poc-test/internal/revocation"
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

// recordingFirebase stands in for Firebase refresh-token revocation.
type recordingFirebase struct{ revoked []string }

func (f *recordingFirebase) RevokeRefreshTokens(_ context.Context, uid string) error {
	f.revoked = append(f.revoked, uid)
	return nil
}

const seededAdmin = "admin.nutfes@gmail.com"

type testEnv struct {
	srv *httptest.Server
	wl  *whitelist.Store
	cl  *clients.Store
	fb  *recordingFirebase
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
	gm2, secret, err := cl.Create(ctx, "GM2", "")
	if err != nil {
		t.Fatal(err)
	}

	fb := &recordingFirebase{}
	s := NewServer(Deps{
		Verifier:  fakeVerifier{},
		Whitelist: wl,
		Clients:   cl,
		Revoker:   revocation.NewNotifier(fb),
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	srv := httptest.NewServer(s.Routes())
	t.Cleanup(srv.Close)
	return &testEnv{srv: srv, wl: wl, cl: cl, fb: fb, clientID: gm2.ID, clientSecret: secret}
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

const member = "22.member.nutfes@gmail.com"

func TestVerifyAutoRegistersNutfesAddressesAndRejectsEveryoneElse(t *testing.T) {
	e := newTestEnv(t)

	tests := []struct {
		token      string
		wantCode   int
		wantStatus string
	}{
		{member, http.StatusOK, StatusAllowed},
		{seededAdmin, http.StatusOK, StatusAllowed},
		{"stranger@gmail.com", http.StatusForbidden, StatusNotNutfesEmail},
		{"s221066@stn.nagaokaut.ac.jp", http.StatusForbidden, StatusNotNutfesEmail},
		{"unverified:" + member, http.StatusForbidden, StatusEmailUnverified},
		{"bad", http.StatusUnauthorized, ""},
	}
	for _, tt := range tests {
		code, status := e.verify(t, tt.token)
		if code != tt.wantCode || status != tt.wantStatus {
			t.Errorf("verify(%s) = %d %q, want %d %q", tt.token, code, status, tt.wantCode, tt.wantStatus)
		}
	}

	entry, err := e.wl.Lookup(context.Background(), member)
	if err != nil || entry.Role != whitelist.RoleMember || entry.AddedBy != whitelist.AddedByAutoRegistration {
		t.Fatalf("first login should auto-register a member, got %+v, %v", entry, err)
	}
	if _, err := e.wl.Lookup(context.Background(), "stranger@gmail.com"); !errors.Is(err, whitelist.ErrNotFound) {
		t.Fatalf("a non-NUTFes address was registered: %v", err)
	}
}

func TestDisabledPeopleStayOutAndCanBeEnabledAgain(t *testing.T) {
	e := newTestEnv(t)
	e.verify(t, member)

	if code, _ := e.as(t, seededAdmin, "POST", "/v1/admin/whitelist/"+member+"/disable", ""); code != http.StatusOK {
		t.Fatalf("disable: got %d", code)
	}
	for i := 0; i < 2; i++ { // the second login must not re-register them
		if code, status := e.verify(t, member); code != http.StatusForbidden || status != StatusDisabled {
			t.Fatalf("login %d after disable: %d %q", i+1, code, status)
		}
	}

	code, body := e.as(t, seededAdmin, "POST", "/v1/admin/whitelist/"+member+"/enable", "")
	if code != http.StatusOK || body["active"] != true {
		t.Fatalf("enable: %d %v", code, body)
	}
	if code, _ := e.verify(t, member); code != http.StatusOK {
		t.Fatalf("login after enable: %d", code)
	}
}

func TestAdminRoutesRequireAnActiveAdmin(t *testing.T) {
	e := newTestEnv(t)
	e.verify(t, member) // auto-registered member
	e.as(t, seededAdmin, "POST", "/v1/admin/whitelist", `{"email":"23.retired.nutfes@gmail.com","role":"admin"}`)
	e.as(t, seededAdmin, "POST", "/v1/admin/whitelist/23.retired.nutfes@gmail.com/disable", "")

	callers := []struct {
		name string
		who  string
		want int
	}{
		{"not signed in", "", http.StatusUnauthorized},
		{"invalid token", "bad", http.StatusUnauthorized},
		{"member", member, http.StatusForbidden},
		{"not a NUTFes address", "stranger@gmail.com", http.StatusForbidden},
		{"admin email but not verified", "unverified:" + seededAdmin, http.StatusForbidden},
		{"disabled admin", "23.retired.nutfes@gmail.com", http.StatusForbidden},
	}
	routes := []struct{ method, path, body string }{
		{"GET", "/v1/admin/whitelist", ""},
		{"POST", "/v1/admin/whitelist", `{"email":"x.nutfes@gmail.com"}`},
		{"PATCH", "/v1/admin/whitelist/" + member, `{"role":"admin"}`},
		{"POST", "/v1/admin/whitelist/" + member + "/disable", ""},
		{"POST", "/v1/admin/whitelist/" + member + "/enable", ""},
		{"POST", "/v1/admin/whitelist/bulk-disable", `{"entry_year_to":30,"dry_run":true}`},
		{"GET", "/v1/admin/clients", ""},
		{"POST", "/v1/admin/clients", `{"name":"X"}`},
		{"PATCH", "/v1/admin/clients/" + e.clientID, `{"is_active":false}`},
		{"POST", "/v1/admin/clients/" + e.clientID + "/secret", ""},
		{"GET", "/v1/admin/logins", ""},
		{"POST", "/v1/admin/logins/revoke", `{"email":"` + member + `"}`},
	}

	for _, c := range callers {
		for _, r := range routes {
			if code, _ := e.raw(t, c.who, r.method, r.path, r.body); code != c.want {
				t.Errorf("%s: %s %s got %d, want %d", c.name, r.method, r.path, code, c.want)
			}
		}
	}

	if code, _ := e.raw(t, "ADMIN.NUTFES@Gmail.com", "GET", "/v1/admin/whitelist", ""); code != http.StatusOK {
		t.Errorf("admin email should match case-insensitively, got %d", code)
	}
}

func TestAdminsCanPromoteAndTheNewAdminCanManage(t *testing.T) {
	e := newTestEnv(t)
	e.verify(t, member)

	code, body := e.as(t, seededAdmin, "PATCH", "/v1/admin/whitelist/"+member, `{"role":"admin"}`)
	if code != http.StatusOK || body["role"] != "admin" {
		t.Fatalf("promote: %d %v", code, body)
	}
	if code, _ := e.raw(t, member, "GET", "/v1/admin/whitelist", ""); code != http.StatusOK {
		t.Fatalf("promoted admin: got %d", code)
	}

	code, body = e.as(t, member, "POST", "/v1/admin/whitelist", `{"email":"24.next.nutfes@gmail.com","role":"admin"}`)
	if code != http.StatusCreated || body["role"] != "admin" || body["added_by"] != member {
		t.Fatalf("add as the new admin: %d %v", code, body)
	}
}

func TestTheLastActiveAdminIsProtected(t *testing.T) {
	e := newTestEnv(t)

	if code, _ := e.as(t, seededAdmin, "POST", "/v1/admin/whitelist/"+seededAdmin+"/disable", ""); code != http.StatusConflict {
		t.Errorf("disable last admin: got %d, want 409", code)
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
		{"POST", "/v1/admin/whitelist", `{"email":"someone@gmail.com"}`, http.StatusBadRequest},
		{"POST", "/v1/admin/whitelist", `{"email":"x.nutfes@gmail.com","role":"owner"}`, http.StatusBadRequest},
		{"PATCH", "/v1/admin/whitelist/" + seededAdmin, `{"role":"owner"}`, http.StatusBadRequest},
		{"PATCH", "/v1/admin/whitelist/ghost.nutfes@gmail.com", `{"role":"admin"}`, http.StatusNotFound},
		{"POST", "/v1/admin/whitelist/ghost.nutfes@gmail.com/disable", "", http.StatusNotFound},
		{"POST", "/v1/admin/whitelist/ghost.nutfes@gmail.com/enable", "", http.StatusNotFound},
	} {
		if code, _ := e.raw(t, seededAdmin, r.method, r.path, r.body); code != r.want {
			t.Errorf("%s %s %s: got %d, want %d", r.method, r.path, r.body, code, r.want)
		}
	}
}

func TestBulkDisable(t *testing.T) {
	e := newTestEnv(t)
	for _, email := range []string{"21.a.nutfes@gmail.com", "22.b.nutfes@gmail.com", "23.c.nutfes@gmail.com", "noyear.nutfes@gmail.com"} {
		e.verify(t, email)
	}
	e.as(t, seededAdmin, "POST", "/v1/admin/whitelist", `{"email":"20.oldadmin.nutfes@gmail.com","role":"admin"}`)

	bulk := func(body string) (int, bulkDisableResponse) {
		t.Helper()
		code, raw := e.raw(t, seededAdmin, "POST", "/v1/admin/whitelist/bulk-disable", body)
		var out bulkDisableResponse
		json.Unmarshal(raw, &out)
		return code, out
	}
	matchedEmails := func(r bulkDisableResponse) []string {
		var out []string
		for _, m := range r.Matched {
			out = append(out, m.Email)
		}
		return out
	}

	code, preview := bulk(`{"entry_year_to":22,"dry_run":true}`)
	if code != http.StatusOK || !preview.DryRun || strings.Join(matchedEmails(preview), ",") != "21.a.nutfes@gmail.com,22.b.nutfes@gmail.com" {
		t.Fatalf("dry run: %d %+v", code, preview)
	}
	if code, _ := e.verify(t, "21.a.nutfes@gmail.com"); code != http.StatusOK {
		t.Fatalf("a dry run must not disable anyone, got %d", code)
	}

	code, done := bulk(`{"entry_year_to":22}`)
	if code != http.StatusOK || done.DryRun || len(done.Results) != 2 {
		t.Fatalf("execute: %d %+v", code, done)
	}
	for _, email := range []string{"21.a.nutfes@gmail.com", "22.b.nutfes@gmail.com"} {
		if code, status := e.verify(t, email); code != http.StatusForbidden || status != StatusDisabled {
			t.Errorf("%s after bulk disable: %d %q", email, code, status)
		}
	}
	for _, email := range []string{"23.c.nutfes@gmail.com", "noyear.nutfes@gmail.com", "20.oldadmin.nutfes@gmail.com"} {
		if code, _ := e.verify(t, email); code != http.StatusOK {
			t.Errorf("%s should be untouched (admins are never bulk-disabled), got %d", email, code)
		}
	}

	today := time.Now().In(jst).Format("2006-01-02")
	if _, byDate := bulk(`{"registered_from":"` + today + `","registered_to":"` + today + `","dry_run":true}`); len(byDate.Matched) != 2 {
		t.Errorf("registered today = %v, want the 2 remaining active members", matchedEmails(byDate))
	}
	if _, byDate := bulk(`{"registered_to":"2000-01-01","dry_run":true}`); len(byDate.Matched) != 0 {
		t.Errorf("registered before 2000 = %v, want none", matchedEmails(byDate))
	}

	for _, body := range []string{`{}`, `{"dry_run":true}`, `{"registered_from":"2026/04/01"}`, `not json`} {
		if code, _ := bulk(body); code != http.StatusBadRequest {
			t.Errorf("bulk %s: got %d, want 400", body, code)
		}
	}
}
