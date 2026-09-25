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
		body       string
		wantStatus string
		wantErr    bool
	}{
		{"approved", 200, `{"sub":"u1","email":"a@example.com","email_verified":true,"status":"approved"}`, "approved", false},
		{"pending", 403, `{"sub":"u1","email":"a@example.com","email_verified":true,"status":"pending"}`, "pending", false},
		{"unverified", 403, `{"sub":"u1","email":"a@example.com","email_verified":false,"status":"email_unverified"}`, "email_unverified", false},
		{"invalid token", 401, `{"error":"invalid id token"}`, StatusInvalid, false},
		{"platform failure", 500, `{"error":"boom"}`, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/v1/auth/verify" {
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
				}
				w.WriteHeader(tt.code)
				w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			got, err := NewClient(srv.URL+"/").Verify(context.Background(), "token")
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

	if _, err := NewClient(url).Verify(context.Background(), "token"); err == nil {
		t.Fatal("want error for unreachable platform")
	}
}
