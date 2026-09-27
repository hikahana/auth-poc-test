package authplatform

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

// sign reproduces what the auth platform sends, independently of the code
// under test.
func sign(secret string, ts int64, body string) string {
	key := sha256.Sum256([]byte(secret))
	mac := hmac.New(sha256.New, []byte(hex.EncodeToString(key[:])))
	fmt.Fprintf(mac, "%d.%s", ts, body)
	return fmt.Sprintf("t=%d,v1=%s", ts, hex.EncodeToString(mac.Sum(nil)))
}

func TestVerifySignature(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	body := `{"event":"user.revoked","sub":"uid-1","email":"a@example.com"}`
	good := sign("cs_secret", now.Unix(), body)

	if err := VerifySignature("cs_secret", good, []byte(body), now); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}

	cases := map[string]struct {
		secret, header, body string
		now                  time.Time
	}{
		"wrong secret":   {"cs_other", good, body, now},
		"tampered body":  {"cs_secret", good, `{"sub":"uid-2"}`, now},
		"stale":          {"cs_secret", good, body, now.Add(6 * time.Minute)},
		"future":         {"cs_secret", good, body, now.Add(-6 * time.Minute)},
		"no header":      {"cs_secret", "", body, now},
		"garbage":        {"cs_secret", "garbage", body, now},
		"secret not set": {"", good, body, now},
	}
	for name, c := range cases {
		if err := VerifySignature(c.secret, c.header, []byte(c.body), c.now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
