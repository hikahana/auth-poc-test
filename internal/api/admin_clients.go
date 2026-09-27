package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/hikahana/auth-poc-test/internal/clients"
	"github.com/hikahana/auth-poc-test/internal/whitelist"
)

func (s *Server) handleListClients(w http.ResponseWriter, r *http.Request) {
	list, err := s.Clients.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed")
		return
	}
	writeJSON(w, http.StatusOK, list)
}

type createClientRequest struct {
	Name      string `json:"name"`
	RevokeURL string `json:"revoke_url"`
}

// clientWithSecret is only ever returned right after a secret is issued.
type clientWithSecret struct {
	clients.Client
	ClientSecret string `json:"client_secret"`
}

func (s *Server) handleCreateClient(w http.ResponseWriter, r *http.Request) {
	var req createClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Name) == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	c, secret, err := s.Clients.Create(r.Context(), req.Name, strings.TrimSpace(req.RevokeURL))
	if s.writeClientError(w, err) {
		return
	}
	writeJSON(w, http.StatusCreated, clientWithSecret{Client: c, ClientSecret: secret})
}

type updateClientRequest struct {
	IsActive  *bool   `json:"is_active"`
	RevokeURL *string `json:"revoke_url"`
}

func (s *Server) handleUpdateClient(w http.ResponseWriter, r *http.Request) {
	var req updateClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || (req.IsActive == nil && req.RevokeURL == nil) {
		writeError(w, http.StatusBadRequest, "is_active or revoke_url is required")
		return
	}
	if req.RevokeURL != nil {
		trimmed := strings.TrimSpace(*req.RevokeURL)
		req.RevokeURL = &trimmed
	}

	c, err := s.Clients.Update(r.Context(), r.PathValue("id"), req.IsActive, req.RevokeURL)
	if s.writeClientError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) handleRotateSecret(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	secret, err := s.Clients.RotateSecret(r.Context(), id)
	if s.writeClientError(w, err) {
		return
	}
	c, err := s.Clients.Get(r.Context(), id)
	if s.writeClientError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, clientWithSecret{Client: c, ClientSecret: secret})
}

func (s *Server) handleListLogins(w http.ResponseWriter, r *http.Request) {
	list, err := s.Clients.Logins(r.Context(), r.URL.Query().Get("email"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed")
		return
	}
	writeJSON(w, http.StatusOK, list)
}

type revokeLoginsRequest struct {
	Email string `json:"email"`
}

// handleRevokeLogins drops a person's sessions in every product without
// touching the whitelist: a "force logout", and the retry path when a
// notification failed during removal.
func (s *Server) handleRevokeLogins(w http.ResponseWriter, r *http.Request) {
	var req revokeLoginsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !strings.Contains(req.Email, "@") {
		writeError(w, http.StatusBadRequest, "email is required")
		return
	}

	email := whitelist.Normalize(req.Email)
	results, err := s.revokeSessions(r, email)
	if err != nil {
		s.Logger.Error("revocation lookup failed", "email", email, "error", err)
		writeError(w, http.StatusInternalServerError, "revocation failed")
		return
	}
	writeJSON(w, http.StatusOK, revocationResponse{Email: email, Revocations: results})
}

// writeClientError reports err (if any) and whether it did.
func (s *Server) writeClientError(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, clients.ErrNotFound):
		writeError(w, http.StatusNotFound, "no such client")
	case errors.Is(err, clients.ErrDuplicateName):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, clients.ErrInvalidRevokeURL):
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		s.Logger.Error("client update failed", "error", err)
		writeError(w, http.StatusInternalServerError, "client update failed")
	}
	return true
}
