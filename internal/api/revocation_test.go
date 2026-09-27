package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/hikahana/auth-poc-test/internal/clients"
	"github.com/hikahana/auth-poc-test/internal/revocation"
)

// fakeProduct receives revocation notifications the way a real product
// would: it checks the signature with its own client secret.
type fakeProduct struct {
	srv    *httptest.Server
	status int
	mu     sync.Mutex
	subs   []string
}

func newFakeProduct(t *testing.T, secret string) *fakeProduct {
	t.Helper()
	p := &fakeProduct{status: http.StatusNoContent}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if err := revocation.Verify(clients.HashSecret(secret), r.Header.Get(revocation.SignatureHeader), body, time.Now()); err != nil {
			t.Errorf("product rejected the notification: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var payload revocation.Payload
		json.Unmarshal(body, &payload)
		p.mu.Lock()
		p.subs = append(p.subs, payload.Sub)
		p.mu.Unlock()
		w.WriteHeader(p.status)
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *fakeProduct) received() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.subs...)
}

type revocationBody struct {
	Email       string              `json:"email"`
	Revocations []revocation.Result `json:"revocations"`
}

func (e *testEnv) revocationCall(t *testing.T, method, path, body string) (int, revocationBody) {
	t.Helper()
	code, raw := e.raw(t, seededAdmin, method, path, body)
	var out revocationBody
	json.Unmarshal(raw, &out)
	return code, out
}

func statuses(rs []revocation.Result) map[string]string {
	m := map[string]string{}
	for _, r := range rs {
		m[r.Target] = r.Status
	}
	return m
}

func TestRemovingFromWhitelistNotifiesEveryProductThePersonUsed(t *testing.T) {
	e := newTestEnv(t)
	gm2 := newFakeProduct(t, e.clientSecret)
	e.as(t, seededAdmin, "PATCH", "/v1/admin/clients/"+e.clientID, `{"revoke_url":"`+gm2.srv.URL+`"}`)

	e.as(t, seededAdmin, "POST", "/v1/admin/whitelist", `{"email":"22.member.nutfes@gmail.com"}`)
	if code, _ := e.verify(t, "22.member.nutfes@gmail.com"); code != http.StatusOK {
		t.Fatalf("login before removal: %d", code)
	}

	code, body := e.revocationCall(t, "POST", "/v1/admin/whitelist/22.Member.NUTFES@gmail.com/disable", "")
	if code != http.StatusOK {
		t.Fatalf("delete: got %d", code)
	}
	if st := statuses(body.Revocations); st["GM2"] != revocation.StatusRevoked || st["Firebase"] != revocation.StatusRevoked {
		t.Fatalf("revocations = %+v", body.Revocations)
	}
	if got := gm2.received(); len(got) != 1 || got[0] != "uid-22.member.nutfes@gmail.com" {
		t.Fatalf("GM2 was told to revoke %v", got)
	}
	if len(e.fb.revoked) != 1 || e.fb.revoked[0] != "uid-22.member.nutfes@gmail.com" {
		t.Fatalf("Firebase revoked %v", e.fb.revoked)
	}
	if code, status := e.verify(t, "22.member.nutfes@gmail.com"); code != http.StatusForbidden || status != StatusDisabled {
		t.Fatalf("login after removal: %d %q", code, status)
	}
}

func TestAFailingProductDoesNotBlockRemovalAndCanBeRetried(t *testing.T) {
	e := newTestEnv(t)
	gm2 := newFakeProduct(t, e.clientSecret)
	gm2.status = http.StatusInternalServerError
	e.as(t, seededAdmin, "PATCH", "/v1/admin/clients/"+e.clientID, `{"revoke_url":"`+gm2.srv.URL+`"}`)

	e.as(t, seededAdmin, "POST", "/v1/admin/whitelist", `{"email":"22.member.nutfes@gmail.com"}`)
	e.verify(t, "22.member.nutfes@gmail.com")

	code, body := e.revocationCall(t, "POST", "/v1/admin/whitelist/22.member.nutfes@gmail.com/disable", "")
	if code != http.StatusOK || statuses(body.Revocations)["GM2"] != revocation.StatusFailed {
		t.Fatalf("delete with failing product: %d %+v", code, body.Revocations)
	}
	if code, _ := e.verify(t, "22.member.nutfes@gmail.com"); code != http.StatusForbidden {
		t.Fatalf("the person must be off the whitelist even though GM2 failed, got %d", code)
	}

	gm2.status = http.StatusNoContent
	code, body = e.revocationCall(t, "POST", "/v1/admin/logins/revoke", `{"email":"22.member.nutfes@gmail.com"}`)
	if code != http.StatusOK || statuses(body.Revocations)["GM2"] != revocation.StatusRevoked {
		t.Fatalf("retry: %d %+v", code, body.Revocations)
	}
	if len(gm2.received()) != 2 {
		t.Fatalf("GM2 received %v, want the failed attempt and the retry", gm2.received())
	}
}

func TestForceLogoutKeepsThePersonOnTheWhitelist(t *testing.T) {
	e := newTestEnv(t)
	gm2 := newFakeProduct(t, e.clientSecret)
	e.as(t, seededAdmin, "PATCH", "/v1/admin/clients/"+e.clientID, `{"revoke_url":"`+gm2.srv.URL+`"}`)
	e.verify(t, seededAdmin)

	code, body := e.revocationCall(t, "POST", "/v1/admin/logins/revoke", `{"email":"`+seededAdmin+`"}`)
	if code != http.StatusOK || statuses(body.Revocations)["GM2"] != revocation.StatusRevoked {
		t.Fatalf("force logout: %d %+v", code, body.Revocations)
	}
	if code, _ := e.verify(t, seededAdmin); code != http.StatusOK {
		t.Fatalf("still whitelisted after force logout, verify got %d", code)
	}
}

func TestRevocationReportsProductsWithoutARevokeURLAsSkipped(t *testing.T) {
	e := newTestEnv(t)
	e.as(t, seededAdmin, "POST", "/v1/admin/whitelist", `{"email":"22.member.nutfes@gmail.com"}`)
	e.verify(t, "22.member.nutfes@gmail.com")

	_, body := e.revocationCall(t, "POST", "/v1/admin/whitelist/22.member.nutfes@gmail.com/disable", "")
	if statuses(body.Revocations)["GM2"] != revocation.StatusSkipped {
		t.Fatalf("revocations = %+v, want GM2 skipped", body.Revocations)
	}

	e.as(t, seededAdmin, "POST", "/v1/admin/whitelist", `{"email":"never-logged-in.nutfes@gmail.com"}`)
	code, body := e.revocationCall(t, "POST", "/v1/admin/whitelist/never-logged-in.nutfes@gmail.com/disable", "")
	if code != http.StatusOK || len(body.Revocations) != 0 {
		t.Fatalf("person who never signed in: %d %+v", code, body.Revocations)
	}
}

func TestRevokeURLValidationOnTheAdminAPI(t *testing.T) {
	e := newTestEnv(t)

	for _, r := range []struct {
		method, path, body string
		want               int
	}{
		{"POST", "/v1/admin/clients", `{"name":"X","revoke_url":"ftp://x"}`, http.StatusBadRequest},
		{"PATCH", "/v1/admin/clients/" + e.clientID, `{"revoke_url":"not a url"}`, http.StatusBadRequest},
		{"POST", "/v1/admin/clients", `{"name":"Y","revoke_url":"https://y.example.com/revoke"}`, http.StatusCreated},
		{"PATCH", "/v1/admin/clients/" + e.clientID, `{"revoke_url":""}`, http.StatusOK},
		{"POST", "/v1/admin/logins/revoke", `{"email":"nope"}`, http.StatusBadRequest},
	} {
		if code, _ := e.raw(t, seededAdmin, r.method, r.path, r.body); code != r.want {
			t.Errorf("%s %s %s: got %d, want %d", r.method, r.path, r.body, code, r.want)
		}
	}
}
