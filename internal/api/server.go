// Package api exposes the two things this platform is responsible for:
// telling a registered product "who is this user" (POST /v1/auth/verify), and
// letting administrators manage the platform (the /v1/admin/* routes).
// Authorization for what a user may do inside a product stays in that
// product — verify never returns product roles or permissions.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/hikahana/auth-poc-test/internal/clients"
	"github.com/hikahana/auth-poc-test/internal/firebaseauth"
	"github.com/hikahana/auth-poc-test/internal/revocation"
	"github.com/hikahana/auth-poc-test/internal/whitelist"
)

type TokenVerifier interface {
	Verify(ctx context.Context, idToken string) (firebaseauth.Identity, error)
}

type Revoker interface {
	Revoke(ctx context.Context, targets []clients.Target) []revocation.Result
}

type Deps struct {
	Verifier  TokenVerifier
	Whitelist *whitelist.Store
	Clients   *clients.Store
	Revoker   Revoker
	WebDir    string
	Logger    *slog.Logger
}

type Server struct {
	Deps
}

func NewServer(d Deps) *Server { return &Server{Deps: d} }

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /v1/auth/verify", s.requireClient(s.handleVerify))

	mux.HandleFunc("GET /v1/admin/whitelist", s.requireAdmin(s.handleListWhitelist))
	mux.HandleFunc("POST /v1/admin/whitelist", s.requireAdmin(s.handleAddWhitelist))
	mux.HandleFunc("PATCH /v1/admin/whitelist/{email}", s.requireAdmin(s.handleSetRole))
	mux.HandleFunc("DELETE /v1/admin/whitelist/{email}", s.requireAdmin(s.handleRemoveWhitelist))

	mux.HandleFunc("GET /v1/admin/clients", s.requireAdmin(s.handleListClients))
	mux.HandleFunc("POST /v1/admin/clients", s.requireAdmin(s.handleCreateClient))
	mux.HandleFunc("PATCH /v1/admin/clients/{id}", s.requireAdmin(s.handleUpdateClient))
	mux.HandleFunc("POST /v1/admin/clients/{id}/secret", s.requireAdmin(s.handleRotateSecret))
	mux.HandleFunc("GET /v1/admin/logins", s.requireAdmin(s.handleListLogins))
	mux.HandleFunc("POST /v1/admin/logins/revoke", s.requireAdmin(s.handleRevokeLogins))

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	if s.WebDir != "" {
		files := http.FileServer(http.Dir(s.WebDir))
		mux.Handle("GET /", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Revalidate every time so an edited test page is never served stale.
			w.Header().Set("Cache-Control", "no-cache")
			files.ServeHTTP(w, r)
		}))
	}

	return mux
}

type clientKey struct{}

// requireClient authenticates the calling product with HTTP Basic auth
// (client_id:client_secret), so only registered, active products can ask
// the platform about a user.
func (s *Server) requireClient(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, secret, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="auth-platform"`)
			writeError(w, http.StatusUnauthorized, "client credentials are required")
			return
		}

		client, err := s.Clients.Authenticate(r.Context(), id, secret)
		if errors.Is(err, clients.ErrInvalidCredentials) {
			w.Header().Set("WWW-Authenticate", `Basic realm="auth-platform"`)
			writeError(w, http.StatusUnauthorized, "invalid client credentials")
			return
		}
		if err != nil {
			s.Logger.Error("client lookup failed", "error", err)
			writeError(w, http.StatusInternalServerError, "client lookup failed")
			return
		}

		next(w, r.WithContext(context.WithValue(r.Context(), clientKey{}, client)))
	}
}

func callingClient(r *http.Request) clients.Client {
	c, _ := r.Context().Value(clientKey{}).(clients.Client)
	return c
}

type adminEmailKey struct{}

// requireAdmin authenticates administrators with their own Google login: the
// request carries a Firebase ID token as a Bearer token, and its verified
// email must be on the whitelist with role=admin. There is no shared secret
// that could leak through the browser.
func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idToken, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || idToken == "" {
			writeError(w, http.StatusUnauthorized, "sign in with Google to use the admin API")
			return
		}

		identity, err := s.Verifier.Verify(r.Context(), idToken)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid id token")
			return
		}
		if !identity.EmailVerified {
			writeError(w, http.StatusForbidden, "not an administrator")
			return
		}

		entry, err := s.Whitelist.Lookup(r.Context(), identity.Email)
		if err != nil && !errors.Is(err, whitelist.ErrNotFound) {
			s.Logger.Error("admin lookup failed", "error", err)
			writeError(w, http.StatusInternalServerError, "admin lookup failed")
			return
		}
		if err != nil || entry.Role != whitelist.RoleAdmin {
			writeError(w, http.StatusForbidden, "not an administrator")
			return
		}

		next(w, r.WithContext(context.WithValue(r.Context(), adminEmailKey{}, entry.Email)))
	}
}

func adminEmail(r *http.Request) string {
	email, _ := r.Context().Value(adminEmailKey{}).(string)
	return email
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
