package api

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestVerifyOnlyAcceptsRegisteredActiveProducts(t *testing.T) {
	e := newTestEnv(t)

	cases := []struct {
		name, id, secret string
		want             int
	}{
		{"registered product", e.clientID, e.clientSecret, http.StatusOK},
		{"no credentials", "", "", http.StatusUnauthorized},
		{"wrong secret", e.clientID, "cs_wrong", http.StatusUnauthorized},
		{"unknown client", "cl_unknown", e.clientSecret, http.StatusUnauthorized},
	}
	for _, c := range cases {
		if code, _ := e.verifyWith(t, c.id, c.secret, seededAdmin); code != c.want {
			t.Errorf("%s: got %d, want %d", c.name, code, c.want)
		}
	}

	if code, _ := e.as(t, seededAdmin, "PATCH", "/v1/admin/clients/"+e.clientID, `{"is_active":false}`); code != http.StatusOK {
		t.Fatalf("deactivate: got %d", code)
	}
	if code, _ := e.verify(t, seededAdmin); code != http.StatusUnauthorized {
		t.Errorf("deactivated product: got %d, want 401", code)
	}
}

func TestVerifyRecordsWhereEachAllowedLoginSignedIn(t *testing.T) {
	e := newTestEnv(t)
	e.as(t, seededAdmin, "POST", "/v1/admin/whitelist", `{"email":"member@example.com"}`)

	_, created := e.as(t, seededAdmin, "POST", "/v1/admin/clients", `{"name":"FinanSu"}`)
	finansuID, finansuSecret := created["id"].(string), created["client_secret"].(string)

	e.verify(t, "member@example.com")
	e.verify(t, "member@example.com")
	e.verifyWith(t, finansuID, finansuSecret, "member@example.com")
	e.verify(t, "stranger@example.com")                           // rejected: not recorded
	e.verify(t, "unverified:member@example.com")                  // rejected: not recorded
	e.verifyWith(t, e.clientID, "cs_wrong", "member@example.com") // bad client: not recorded

	_, raw := e.raw(t, seededAdmin, "GET", "/v1/admin/logins?email=member@example.com", "")
	var logins []map[string]any
	if err := json.Unmarshal(raw, &logins); err != nil {
		t.Fatal(err)
	}
	if len(logins) != 2 || logins[0]["client_name"] != "FinanSu" || logins[1]["client_name"] != "GM2" {
		t.Fatalf("logins = %v, want one row each for FinanSu and GM2", logins)
	}
	if logins[1]["sub"] != "uid-member@example.com" {
		t.Errorf("sub = %v", logins[1]["sub"])
	}

	_, raw = e.raw(t, seededAdmin, "GET", "/v1/admin/logins", "")
	var all []map[string]any
	json.Unmarshal(raw, &all)
	if len(all) != 2 {
		t.Fatalf("all logins = %v, want only the two allowed ones", all)
	}
}

func TestAdminClientManagement(t *testing.T) {
	e := newTestEnv(t)

	code, created := e.as(t, seededAdmin, "POST", "/v1/admin/clients", `{"name":"FinanSu"}`)
	if code != http.StatusCreated || created["client_secret"] == "" || created["id"] == "" {
		t.Fatalf("create: %d %v", code, created)
	}
	id, secret := created["id"].(string), created["client_secret"].(string)

	_, raw := e.raw(t, seededAdmin, "GET", "/v1/admin/clients", "")
	var list []map[string]any
	json.Unmarshal(raw, &list)
	if len(list) != 2 {
		t.Fatalf("list = %v, want GM2 and FinanSu", list)
	}
	for _, c := range list {
		if _, leaked := c["client_secret"]; leaked {
			t.Fatalf("list exposes a secret: %v", c)
		}
	}

	code, rotated := e.as(t, seededAdmin, "POST", "/v1/admin/clients/"+id+"/secret", "")
	if code != http.StatusOK || rotated["client_secret"] == secret {
		t.Fatalf("rotate: %d %v", code, rotated)
	}
	if code, _ := e.verifyWith(t, id, secret, seededAdmin); code != http.StatusUnauthorized {
		t.Errorf("old secret after rotation: got %d, want 401", code)
	}
	if code, _ := e.verifyWith(t, id, rotated["client_secret"].(string), seededAdmin); code != http.StatusOK {
		t.Errorf("new secret: got %d, want 200", code)
	}

	for _, r := range []struct {
		method, path, body string
		want               int
	}{
		{"POST", "/v1/admin/clients", `{"name":"FinanSu"}`, http.StatusConflict},
		{"POST", "/v1/admin/clients", `{"name":"  "}`, http.StatusBadRequest},
		{"PATCH", "/v1/admin/clients/cl_unknown", `{"is_active":false}`, http.StatusNotFound},
		{"PATCH", "/v1/admin/clients/" + id, `{}`, http.StatusBadRequest},
		{"POST", "/v1/admin/clients/cl_unknown/secret", "", http.StatusNotFound},
	} {
		if code, _ := e.raw(t, seededAdmin, r.method, r.path, r.body); code != r.want {
			t.Errorf("%s %s %s: got %d, want %d", r.method, r.path, r.body, code, r.want)
		}
	}
}
