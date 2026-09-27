// Package authplatform calls the shared auth platform's POST /v1/auth/verify.
package authplatform

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// StatusAllowed is the platform's only success status (the others are
// not_nutfes_email, disabled and email_unverified); StatusInvalid is set by this client
// when the platform rejects the token itself.
const (
	StatusAllowed = "allowed"
	StatusInvalid = "invalid"
)

type Result struct {
	Status        string `json:"status"`
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

type Client struct {
	baseURL      string
	clientID     string
	clientSecret string
	http         *http.Client
}

// NewClient takes FinanSu's own credentials as registered on the platform.
func NewClient(baseURL, clientID, clientSecret string) *Client {
	return &Client{
		baseURL:      strings.TrimRight(baseURL, "/"),
		clientID:     clientID,
		clientSecret: clientSecret,
		http:         &http.Client{Timeout: 5 * time.Second},
	}
}

// Verify returns an error only when the platform could not give an answer
// (unreachable, 5xx). A rejected login is a Result, not an error.
func (c *Client) Verify(ctx context.Context, idToken string) (Result, error) {
	body, _ := json.Marshal(map[string]string{"id_token": idToken})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/auth/verify", bytes.NewReader(body))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(c.clientID, c.clientSecret)

	res, err := c.http.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("call auth platform: %w", err)
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK, http.StatusForbidden:
		var r Result
		if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
			return Result{}, fmt.Errorf("decode auth platform response: %w", err)
		}
		return r, nil
	case http.StatusUnauthorized:
		// The platform challenges with WWW-Authenticate only when FinanSu's own
		// client credentials are wrong — a misconfiguration, not the user's fault.
		if res.Header.Get("WWW-Authenticate") != "" {
			return Result{}, fmt.Errorf("auth platform rejected the client credentials; check AUTH_PLATFORM_CLIENT_ID/SECRET")
		}
		return Result{Status: StatusInvalid}, nil
	default:
		return Result{}, fmt.Errorf("auth platform returned %d", res.StatusCode)
	}
}
