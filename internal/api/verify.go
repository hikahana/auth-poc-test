package api

import (
	"encoding/json"
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
	StatusNotNutfesEmail  = "not_nutfes_email"
	StatusDisabled        = "disabled"
	StatusEmailUnverified = "email_unverified"
)

// handleVerify is the endpoint every registered product calls after the
// Firebase Client SDK hands it an ID token. It verifies the token's
// signature/expiry with Firebase, lets only NUTFes addresses through,
// registers a first-time NUTFes address as a member, and refuses anyone an
// administrator has disabled. Only status=allowed should be treated as a
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
	// register someone else's NUTFes address in Firebase and pass as them.
	if identity.Email == "" || !identity.EmailVerified {
		resp.Status = StatusEmailUnverified
		writeJSON(w, http.StatusForbidden, resp)
		return
	}

	if !whitelist.Eligible(identity.Email) {
		resp.Status = StatusNotNutfesEmail
		writeJSON(w, http.StatusForbidden, resp)
		return
	}

	entry, err := s.Whitelist.EnsureMember(r.Context(), identity.Email)
	if err != nil {
		s.Logger.Error("whitelist registration failed", "error", err)
		writeError(w, http.StatusInternalServerError, "whitelist lookup failed")
		return
	}
	if !entry.Active {
		resp.Status = StatusDisabled
		writeJSON(w, http.StatusForbidden, resp)
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
