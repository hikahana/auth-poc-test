package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/hikahana/auth-poc-test/internal/clients"
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
	Name string `json:"name"`
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

	c, secret, err := s.Clients.Create(r.Context(), req.Name)
	if s.writeClientError(w, err) {
		return
	}
	writeJSON(w, http.StatusCreated, clientWithSecret{Client: c, ClientSecret: secret})
}

type updateClientRequest struct {
	IsActive *bool `json:"is_active"`
}

func (s *Server) handleUpdateClient(w http.ResponseWriter, r *http.Request) {
	var req updateClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IsActive == nil {
		writeError(w, http.StatusBadRequest, "is_active is required")
		return
	}

	c, err := s.Clients.SetActive(r.Context(), r.PathValue("id"), *req.IsActive)
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

// writeClientError reports err (if any) and whether it did.
func (s *Server) writeClientError(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, clients.ErrNotFound):
		writeError(w, http.StatusNotFound, "no such client")
	case errors.Is(err, clients.ErrDuplicateName):
		writeError(w, http.StatusConflict, err.Error())
	default:
		s.Logger.Error("client update failed", "error", err)
		writeError(w, http.StatusInternalServerError, "client update failed")
	}
	return true
}
