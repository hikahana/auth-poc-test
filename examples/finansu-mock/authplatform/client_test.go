package authplatform

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVerifyMapsPlatformResponses(t *testing.T) {
	tests := []struct {
		name       string
		code       int
		challenge  bool
		body       string
		wantStatus string
		wantErr    bool
	}{
		{"allowed", 200, false, `{"sub":"u1","email":"a@example.com","email_verified":true,"status":"allowed"}`, StatusAllowed, false},
		{"disabled", 403, false, `{"sub":"u1","email":"a.nutfes@gmail.com","email_verified":true,"status":"disabled"}`, "disabled", false},
		{"not a NUTFes address", 403, false, `{"sub":"u1","email":"a@gmail.com","email_verified":true,"status":"not_nutfes_email"}`, "not_nutfes_email", false},
		{"unverified", 403, false, `{"sub":"u1","email":"a@example.com","email_verified":false,"status":"email_unverified"}`, "email_unverified", false},
		{"invalid token", 401, false, `{"error":"invalid id token"}`, StatusInvalid, false},
		{"FinanSu's own credentials rejected", 401, true, `{"error":"invalid client credentials"}`, "", true},
		{"platform failure", 500, false, `{"error":"boom"}`, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/v1/auth/verify" {
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
				}
				if id, secret, ok := r.BasicAuth(); !ok || id != "cl_finansu" || secret != "cs_secret" {
					t.Errorf("client credentials not sent: %q %q %v", id, secret, ok)
				}
				if tt.challenge {
					w.Header().Set("WWW-Authenticate", `Basic realm="auth-platform"`)
				}
				w.WriteHeader(tt.code)
				w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			got, err := NewClient(srv.URL+"/", "cl_finansu", "cs_secret").Verify(context.Background(), "token")
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got.Status != tt.wantStatus {
				t.Fatalf("status = %q, want %q", got.Status, tt.wantStatus)
			}
		})
	}
}

func TestVerifyUnreachablePlatformIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()

	if _, err := NewClient(url, "id", "secret").Verify(context.Background(), "token"); err == nil {
		t.Fatal("want error for unreachable platform")
	}
}
