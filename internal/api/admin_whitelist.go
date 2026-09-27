package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

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

func (s *Server) handleRemoveWhitelist(w http.ResponseWriter, r *http.Request) {
	err := s.Whitelist.Remove(r.Context(), r.PathValue("email"))
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
		s.Logger.Error("whitelist update failed", "error", err)
		writeError(w, http.StatusInternalServerError, "whitelist update failed")
	}
	return true
}
