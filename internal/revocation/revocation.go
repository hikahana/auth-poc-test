// Package revocation tells products to drop a user's sessions, so removing an
// email from the whitelist takes effect immediately instead of when each
// product's own session expires. The platform keeps no sessions itself; it
// uses the recorded (login, product) pairs to know whom to notify.
//
// Each notification is a signed POST to the product's revoke_url:
//
//	POST <revoke_url>
//	Content-Type: application/json
//	X-Auth-Platform-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256>
//
//	{"event":"user.revoked","sub":"<Firebase UID>","email":"<email>"}
//
// The HMAC key is SHA-256(client_secret) as lowercase hex, and the signed
// message is "<t>.<raw body>". Products should reject timestamps more than
// Tolerance away from their clock.
package revocation

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hikahana/auth-poc-test/internal/clients"
)

const (
	SignatureHeader = "X-Auth-Platform-Signature"
	EventRevoked    = "user.revoked"
	Tolerance       = 5 * time.Minute
)

type Payload struct {
	Event string `json:"event"`
	Sub   string `json:"sub"`
	Email string `json:"email"`
}

func Sign(signingKey string, timestamp int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(signingKey))
	fmt.Fprintf(mac, "%d.", timestamp)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify is the check a product performs on an incoming notification. It
// lives here as the reference implementation and for tests.
func Verify(signingKey, header string, body []byte, now time.Time) error {
	var ts int64
	var sig string
	for _, part := range strings.Split(header, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch k {
		case "t":
			ts, _ = strconv.ParseInt(v, 10, 64)
		case "v1":
			sig = v
		}
	}
	if ts == 0 || sig == "" {
		return errors.New("malformed signature header")
	}
	if d := now.Sub(time.Unix(ts, 0)); d > Tolerance || d < -Tolerance {
		return errors.New("signature timestamp outside tolerance")
	}
	if !hmac.Equal([]byte(sig), []byte(Sign(signingKey, ts, body))) {
		return errors.New("signature mismatch")
	}
	return nil
}

const (
	StatusRevoked = "revoked"
	StatusFailed  = "failed"
	StatusSkipped = "skipped"
)

// Result reports what happened at one destination. Target is a product name,
// or "Firebase" for the refresh-token revocation.
type Result struct {
	Target string `json:"target"`
	Sub    string `json:"sub"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type FirebaseRevoker interface {
	RevokeRefreshTokens(ctx context.Context, uid string) error
}

type Notifier struct {
	HTTP     *http.Client
	Firebase FirebaseRevoker
	Now      func() time.Time
}

func NewNotifier(firebase FirebaseRevoker) *Notifier {
	return &Notifier{HTTP: &http.Client{Timeout: 5 * time.Second}, Firebase: firebase, Now: time.Now}
}

// Revoke drops every session it can reach and reports each attempt. It never
// stops early: one unreachable product must not keep the others signed in.
func (n *Notifier) Revoke(ctx context.Context, targets []clients.Target) []Result {
	results := []Result{}

	// Revoking Firebase refresh tokens stops the browser from minting new ID
	// tokens, so no product can be signed in to again with the old login.
	seen := map[string]bool{}
	for _, t := range targets {
		if seen[t.Sub] {
			continue
		}
		seen[t.Sub] = true
		r := Result{Target: "Firebase", Sub: t.Sub, Status: StatusRevoked}
		if err := n.Firebase.RevokeRefreshTokens(ctx, t.Sub); err != nil {
			r.Status, r.Detail = StatusFailed, err.Error()
		}
		results = append(results, r)
	}

	for _, t := range targets {
		results = append(results, n.notify(ctx, t))
	}
	return results
}

func (n *Notifier) notify(ctx context.Context, t clients.Target) Result {
	r := Result{Target: t.ClientName, Sub: t.Sub}
	if t.RevokeURL == "" {
		r.Status, r.Detail = StatusSkipped, "no revoke_url registered for this product"
		return r
	}

	body, _ := json.Marshal(Payload{Event: EventRevoked, Sub: t.Sub, Email: t.Email})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.RevokeURL, bytes.NewReader(body))
	if err != nil {
		r.Status, r.Detail = StatusFailed, err.Error()
		return r
	}
	ts := n.Now().Unix()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(SignatureHeader, fmt.Sprintf("t=%d,v1=%s", ts, Sign(t.SigningKey, ts, body)))

	res, err := n.HTTP.Do(req)
	if err != nil {
		r.Status, r.Detail = StatusFailed, err.Error()
		return r
	}
	res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		r.Status, r.Detail = StatusFailed, fmt.Sprintf("product returned HTTP %d", res.StatusCode)
		return r
	}
	r.Status = StatusRevoked
	return r
}
