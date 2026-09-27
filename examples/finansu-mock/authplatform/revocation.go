package authplatform

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// SignatureHeader carries the auth platform's signature on a revocation
// notification: "t=<unix seconds>,v1=<hex HMAC-SHA256>".
const SignatureHeader = "X-Auth-Platform-Signature"

const signatureTolerance = 5 * time.Minute

// RevocationPayload is the body of a "drop this user's sessions" notification.
type RevocationPayload struct {
	Event string `json:"event"`
	Sub   string `json:"sub"`
	Email string `json:"email"`
}

const EventRevoked = "user.revoked"

// VerifySignature checks a notification with FinanSu's own client secret. The
// HMAC key is SHA-256(secret) as lowercase hex, and the signed message is
// "<t>.<raw body>"; notifications older or newer than 5 minutes are rejected.
func VerifySignature(clientSecret, header string, body []byte, now time.Time) error {
	if clientSecret == "" {
		return errors.New("AUTH_PLATFORM_CLIENT_SECRET is not set")
	}

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
	if d := now.Sub(time.Unix(ts, 0)); d > signatureTolerance || d < -signatureTolerance {
		return errors.New("signature timestamp outside tolerance")
	}

	key := sha256.Sum256([]byte(clientSecret))
	mac := hmac.New(sha256.New, []byte(hex.EncodeToString(key[:])))
	fmt.Fprintf(mac, "%d.", ts)
	mac.Write(body)
	if !hmac.Equal([]byte(sig), []byte(hex.EncodeToString(mac.Sum(nil)))) {
		return errors.New("signature mismatch")
	}
	return nil
}
