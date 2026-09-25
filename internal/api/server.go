// Package api exposes the two things this platform is responsible for:
// telling a client product "who is this user" (POST /v1/auth/verify), and
// letting an operator manage the email whitelist (the /v1/admin/* routes).
// Authorization for what a user is allowed to do stays in each product —
// this API never returns roles or permissions, only a verified identity.
package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/hikahana/auth-poc-test/internal/firebaseauth"
	"github.com/hikahana/auth-poc-test/internal/whitelist"
)

type Server struct {
	verifier    *firebaseauth.Verifier
	whitelist   *whitelist.Store
	adminAPIKey string
	webDir      string
	logger      *slog.Logger
}

func NewServer(verifier *firebaseauth.Verifier, wl *whitelist.Store, adminAPIKey, webDir string, logger *slog.Logger) *Server {
	return &Server{verifier: verifier, whitelist: wl, adminAPIKey: adminAPIKey, webDir: webDir, logger: logger}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /v1/auth/verify", s.handleVerify)

	mux.HandleFunc("GET /v1/admin/whitelist", s.requireAdmin(s.handleListWhitelist))
	mux.HandleFunc("POST /v1/admin/whitelist", s.requireAdmin(s.handleAddWhitelist))
	mux.HandleFunc("POST /v1/admin/whitelist/approve", s.requireAdmin(s.handleApprove))
	mux.HandleFunc("POST /v1/admin/whitelist/reject", s.requireAdmin(s.handleReject))

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	if s.webDir != "" {
		mux.Handle("GET /", http.FileServer(http.Dir(s.webDir)))
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
	Sub    string `json:"sub"`
	Email  string `json:"email"`
	Status string `json:"status"`
}

// handleVerify is the endpoint every client product calls after Firebase
// Client SDK hands it an ID token. It verifies the token's signature/expiry
// with Firebase, then checks (and lazily registers) the email against the
// whitelist. Only status=approved should be treated as a successful login by
// the caller.
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

	entry, err := s.whitelist.EnsureEntry(r.Context(), identity.Email)
	if err != nil {
		s.logger.Error("whitelist lookup failed", "error", err)
		writeError(w, http.StatusInternalServerError, "whitelist lookup failed")
		return
	}

	resp := verifyResponse{Sub: identity.Sub, Email: identity.Email, Status: string(entry.Status)}

	if entry.Status != whitelist.StatusApproved {
		writeJSON(w, http.StatusForbidden, resp)
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleListWhitelist(w http.ResponseWriter, r *http.Request) {
	status := whitelist.Status(r.URL.Query().Get("status"))

	entries, err := s.whitelist.List(r.Context(), status)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed")
		return
	}

	writeJSON(w, http.StatusOK, entries)
}

type addWhitelistRequest struct {
	Email string `json:"email"`
}

func (s *Server) handleAddWhitelist(w http.ResponseWriter, r *http.Request) {
	var req addWhitelistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
		writeError(w, http.StatusBadRequest, "email is required")
		return
	}

	entry, err := s.whitelist.EnsureEntry(r.Context(), req.Email)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "insert failed")
		return
	}

	writeJSON(w, http.StatusCreated, entry)
}

type reviewRequest struct {
	Email      string `json:"email"`
	ApprovedBy string `json:"approved_by"`
}

func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	s.review(w, r, whitelist.StatusApproved)
}

func (s *Server) handleReject(w http.ResponseWriter, r *http.Request) {
	s.review(w, r, whitelist.StatusRejected)
}

func (s *Server) review(w http.ResponseWriter, r *http.Request, status whitelist.Status) {
	var req reviewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" || req.ApprovedBy == "" {
		writeError(w, http.StatusBadRequest, "email and approved_by are required")
		return
	}

	err := s.whitelist.SetStatus(r.Context(), req.Email, status, req.ApprovedBy)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "no such whitelist entry")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "update failed")
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
