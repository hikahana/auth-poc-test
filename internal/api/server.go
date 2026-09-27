// Package api exposes the two things this platform is responsible for:
// telling a client product "who is this user" (POST /v1/auth/verify), and
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

	"github.com/hikahana/auth-poc-test/internal/firebaseauth"
	"github.com/hikahana/auth-poc-test/internal/whitelist"
)

type TokenVerifier interface {
	Verify(ctx context.Context, idToken string) (firebaseauth.Identity, error)
}

type Server struct {
	verifier  TokenVerifier
	whitelist *whitelist.Store
	webDir    string
	logger    *slog.Logger
}

func NewServer(verifier TokenVerifier, wl *whitelist.Store, webDir string, logger *slog.Logger) *Server {
	return &Server{verifier: verifier, whitelist: wl, webDir: webDir, logger: logger}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /v1/auth/verify", s.handleVerify)

	mux.HandleFunc("GET /v1/admin/whitelist", s.requireAdmin(s.handleListWhitelist))
	mux.HandleFunc("POST /v1/admin/whitelist", s.requireAdmin(s.handleAddWhitelist))
	mux.HandleFunc("PATCH /v1/admin/whitelist/{email}", s.requireAdmin(s.handleSetRole))
	mux.HandleFunc("DELETE /v1/admin/whitelist/{email}", s.requireAdmin(s.handleRemoveWhitelist))

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	if s.webDir != "" {
		files := http.FileServer(http.Dir(s.webDir))
		mux.Handle("GET /", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Revalidate every time so an edited test page is never served stale.
			w.Header().Set("Cache-Control", "no-cache")
			files.ServeHTTP(w, r)
		}))
	}

	return mux
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

		identity, err := s.verifier.Verify(r.Context(), idToken)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid id token")
			return
		}
		if !identity.EmailVerified {
			writeError(w, http.StatusForbidden, "not an administrator")
			return
		}

		entry, err := s.whitelist.Lookup(r.Context(), identity.Email)
		if err != nil && !errors.Is(err, whitelist.ErrNotFound) {
			s.logger.Error("admin lookup failed", "error", err)
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

type verifyRequest struct {
	IDToken string `json:"id_token"`
}

type verifyResponse struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Status        string `json:"status"`
}

const (
	StatusAllowed         = "allowed"
	StatusNotWhitelisted  = "not_whitelisted"
	StatusEmailUnverified = "email_unverified"
)

// handleVerify is the endpoint every client product calls after Firebase
// Client SDK hands it an ID token. It verifies the token's signature/expiry
// with Firebase, then checks the email against the pre-registered whitelist.
// Only status=allowed should be treated as a successful login by the caller.
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req verifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IDToken == "" {
		writeError(w, http.StatusBadRequest, "id_token is required")
		return
	}

	identity, err := s.verifier.Verify(r.Context(), req.IDToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid id token")
		return
	}

	resp := verifyResponse{Sub: identity.Sub, Email: identity.Email, EmailVerified: identity.EmailVerified}

	// The whitelist is keyed by email, and Firebase email/password sign-up does
	// not prove ownership of the address. Without this check anyone could
	// register a whitelisted address in Firebase and pass.
	if identity.Email == "" || !identity.EmailVerified {
		resp.Status = StatusEmailUnverified
		writeJSON(w, http.StatusForbidden, resp)
		return
	}

	_, err = s.whitelist.Lookup(r.Context(), identity.Email)
	if errors.Is(err, whitelist.ErrNotFound) {
		resp.Status = StatusNotWhitelisted
		writeJSON(w, http.StatusForbidden, resp)
		return
	}
	if err != nil {
		s.logger.Error("whitelist lookup failed", "error", err)
		writeError(w, http.StatusInternalServerError, "whitelist lookup failed")
		return
	}

	resp.Status = StatusAllowed
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleListWhitelist(w http.ResponseWriter, r *http.Request) {
	entries, err := s.whitelist.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed")
		return
	}

	writeJSON(w, http.StatusOK, entries)
}

type addWhitelistRequest struct {
	Email string         `json:"email"`
	Role  whitelist.Role `json:"role"`
}

func (s *Server) handleAddWhitelist(w http.ResponseWriter, r *http.Request) {
	var req addWhitelistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !strings.Contains(req.Email, "@") {
		writeError(w, http.StatusBadRequest, "email is required")
		return
	}
	if req.Role == "" {
		req.Role = whitelist.RoleMember
	}
	if !req.Role.Valid() {
		writeError(w, http.StatusBadRequest, "role must be member or admin")
		return
	}

	entry, err := s.whitelist.Add(r.Context(), req.Email, req.Role, adminEmail(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "insert failed")
		return
	}

	writeJSON(w, http.StatusCreated, entry)
}

type setRoleRequest struct {
	Role whitelist.Role `json:"role"`
}

func (s *Server) handleSetRole(w http.ResponseWriter, r *http.Request) {
	var req setRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !req.Role.Valid() {
		writeError(w, http.StatusBadRequest, "role must be member or admin")
		return
	}

	entry, err := s.whitelist.SetRole(r.Context(), r.PathValue("email"), req.Role)
	if s.writeWhitelistError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, entry)
}

func (s *Server) handleRemoveWhitelist(w http.ResponseWriter, r *http.Request) {
	err := s.whitelist.Remove(r.Context(), r.PathValue("email"))
	if s.writeWhitelistError(w, err) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// writeWhitelistError reports err (if any) and whether it did.
func (s *Server) writeWhitelistError(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, whitelist.ErrNotFound):
		writeError(w, http.StatusNotFound, "no such whitelist entry")
	case errors.Is(err, whitelist.ErrLastAdmin):
		writeError(w, http.StatusConflict, err.Error())
	default:
		s.logger.Error("whitelist update failed", "error", err)
		writeError(w, http.StatusInternalServerError, "whitelist update failed")
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
