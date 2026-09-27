package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/hikahana/auth-poc-test/internal/revocation"
	"github.com/hikahana/auth-poc-test/internal/whitelist"
)

func (s *Server) handleListWhitelist(w http.ResponseWriter, r *http.Request) {
	entries, err := s.Whitelist.List(r.Context())
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

	entry, err := s.Whitelist.Add(r.Context(), req.Email, req.Role, adminEmail(r))
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

	entry, err := s.Whitelist.SetRole(r.Context(), r.PathValue("email"), req.Role)
	if s.writeWhitelistError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, entry)
}

type revocationResponse struct {
	Email       string              `json:"email"`
	Revocations []revocation.Result `json:"revocations"`
}

// handleRemoveWhitelist removes the address first, so no new login can get
// through, and then drops the sessions the person already holds in each
// product. The per-product outcome is returned so the admin can see (and
// retry via POST /v1/admin/logins/revoke) anything that failed.
func (s *Server) handleRemoveWhitelist(w http.ResponseWriter, r *http.Request) {
	email := whitelist.Normalize(r.PathValue("email"))
	err := s.Whitelist.Remove(r.Context(), email)
	if s.writeWhitelistError(w, err) {
		return
	}

	results, err := s.revokeSessions(r, email)
	if err != nil {
		s.Logger.Error("removed from whitelist but revocation lookup failed", "email", email, "error", err)
		writeError(w, http.StatusInternalServerError, "removed from the whitelist, but existing sessions could not be revoked; retry with force logout")
		return
	}
	writeJSON(w, http.StatusOK, revocationResponse{Email: email, Revocations: results})
}

func (s *Server) revokeSessions(r *http.Request, email string) ([]revocation.Result, error) {
	targets, err := s.Clients.RevocationTargets(r.Context(), email)
	if err != nil {
		return nil, err
	}
	results := s.Revoker.Revoke(r.Context(), targets)
	for _, res := range results {
		if res.Status == revocation.StatusFailed {
			s.Logger.Warn("session revocation failed", "email", email, "target", res.Target, "detail", res.Detail)
		}
	}
	return results, nil
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
		s.Logger.Error("whitelist update failed", "error", err)
		writeError(w, http.StatusInternalServerError, "whitelist update failed")
	}
	return true
}
