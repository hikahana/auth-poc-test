// Package api exposes the two things this platform is responsible for:
// telling a client product "who is this user" (POST /v1/auth/verify), and
// letting an operator manage the email whitelist (the /v1/admin/* routes).
// Authorization for what a user is allowed to do stays in each product —
// this API never returns roles or permissions, only a verified identity.
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
	verifier    TokenVerifier
	whitelist   *whitelist.Store
	adminAPIKey string
	webDir      string
	logger      *slog.Logger
}

func NewServer(verifier TokenVerifier, wl *whitelist.Store, adminAPIKey, webDir string, logger *slog.Logger) *Server {
	return &Server{verifier: verifier, whitelist: wl, adminAPIKey: adminAPIKey, webDir: webDir, logger: logger}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /v1/auth/verify", s.handleVerify)

	mux.HandleFunc("GET /v1/admin/whitelist", s.requireAdmin(s.handleListWhitelist))
	mux.HandleFunc("POST /v1/admin/whitelist", s.requireAdmin(s.handleAddWhitelist))
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

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.adminAPIKey == "" || r.Header.Get("X-Admin-Key") != s.adminAPIKey {
			writeError(w, http.StatusUnauthorized, "invalid or missing admin key")
			return
		}
		next(w, r)
	}
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
	// register an approved address in Firebase and pass the whitelist.
	if identity.Email == "" || !identity.EmailVerified {
		resp.Status = StatusEmailUnverified
		writeJSON(w, http.StatusForbidden, resp)
		return
	}

	allowed, err := s.whitelist.IsAllowed(r.Context(), identity.Email)
	if err != nil {
		s.logger.Error("whitelist lookup failed", "error", err)
		writeError(w, http.StatusInternalServerError, "whitelist lookup failed")
		return
	}

	if !allowed {
		resp.Status = StatusNotWhitelisted
		writeJSON(w, http.StatusForbidden, resp)
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
	Email   string `json:"email"`
	AddedBy string `json:"added_by"`
}

func (s *Server) handleAddWhitelist(w http.ResponseWriter, r *http.Request) {
	var req addWhitelistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !strings.Contains(req.Email, "@") || req.AddedBy == "" {
		writeError(w, http.StatusBadRequest, "email and added_by are required")
		return
	}

	entry, err := s.whitelist.Add(r.Context(), req.Email, req.AddedBy)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "insert failed")
		return
	}

	writeJSON(w, http.StatusCreated, entry)
}

func (s *Server) handleRemoveWhitelist(w http.ResponseWriter, r *http.Request) {
	err := s.whitelist.Remove(r.Context(), r.PathValue("email"))
	if errors.Is(err, whitelist.ErrNotFound) {
		writeError(w, http.StatusNotFound, "no such whitelist entry")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "delete failed")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
