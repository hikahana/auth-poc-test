package api

import (
	"encoding/json"
	"net/http"
)

type googleSignInRequest struct {
	Credential string `json:"credential"`
}

type googleSignInResponse struct {
	Email       string `json:"email"`
	Status      string `json:"status"`
	CustomToken string `json:"custom_token,omitempty"`
}

// handleGoogleSignIn is where the browser sends the Google ID token it got
// from Google Identity Services. The whitelist is applied here, before
// Firebase is involved, so someone it refuses never gets a Firebase user.
// Someone it lets through gets a custom token to sign in to Firebase with
// (signInWithCustomToken); from there the products' flow is unchanged
// (Firebase ID token -> POST /v1/auth/verify).
//
// It needs no client credentials: it is called from the browser, and a
// custom token only grants a Firebase session that verify checks again.
func (s *Server) handleGoogleSignIn(w http.ResponseWriter, r *http.Request) {
	var req googleSignInRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Credential == "" {
		writeError(w, http.StatusBadRequest, "credential is required")
		return
	}

	identity, err := s.Google.Verify(r.Context(), req.Credential)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid google id token")
		return
	}

	resp := googleSignInResponse{Email: identity.Email}

	resp.Status, err = s.admit(r.Context(), identity.Email, identity.EmailVerified)
	if err != nil {
		s.Logger.Error("whitelist registration failed", "error", err)
		writeError(w, http.StatusInternalServerError, "whitelist lookup failed")
		return
	}
	if resp.Status != StatusAllowed {
		writeJSON(w, http.StatusForbidden, resp)
		return
	}

	resp.CustomToken, err = s.CustomTokens.CustomTokenFor(r.Context(), identity.Email)
	if err != nil {
		s.Logger.Error("issuing firebase custom token failed", "error", err)
		writeError(w, http.StatusInternalServerError, "firebase sign-in failed")
		return
	}

	writeJSON(w, http.StatusOK, resp)
}
