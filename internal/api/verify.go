package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/hikahana/auth-poc-test/internal/whitelist"
)

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

// handleVerify is the endpoint every registered product calls after the
// Firebase Client SDK hands it an ID token. It verifies the token's
// signature/expiry with Firebase, then checks the email against the
// pre-registered whitelist. Only status=allowed should be treated as a
// successful login by the caller; each allowed login is recorded against the
// calling product.
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req verifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IDToken == "" {
		writeError(w, http.StatusBadRequest, "id_token is required")
		return
	}

	identity, err := s.Verifier.Verify(r.Context(), req.IDToken)
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

	_, err = s.Whitelist.Lookup(r.Context(), identity.Email)
	if errors.Is(err, whitelist.ErrNotFound) {
		resp.Status = StatusNotWhitelisted
		writeJSON(w, http.StatusForbidden, resp)
		return
	}
	if err != nil {
		s.Logger.Error("whitelist lookup failed", "error", err)
		writeError(w, http.StatusInternalServerError, "whitelist lookup failed")
		return
	}

	// Fail closed: a login the platform has not recorded is one it could not
	// revoke later, so it is not allowed through.
	if err := s.Clients.RecordLogin(r.Context(), identity.Sub, callingClient(r).ID, identity.Email); err != nil {
		s.Logger.Error("recording login failed", "error", err)
		writeError(w, http.StatusInternalServerError, "recording login failed")
		return
	}

	resp.Status = StatusAllowed
	writeJSON(w, http.StatusOK, resp)
}
