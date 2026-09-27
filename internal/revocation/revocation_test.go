package revocation

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hikahana/auth-poc-test/internal/clients"
)

var fixedNow = time.Unix(1_800_000_000, 0)

func TestVerifyAcceptsOnlyFreshCorrectSignatures(t *testing.T) {
	key := clients.HashSecret("cs_secret")
	body := []byte(`{"event":"user.revoked","sub":"uid-1","email":"a@example.com"}`)
	ts := fixedNow.Unix()
	good := "t=1800000000,v1=" + Sign(key, ts, body)

	if err := Verify(key, good, body, fixedNow); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	cases := map[string]struct {
		key, header string
		body        []byte
		now         time.Time
	}{
		"wrong key":       {clients.HashSecret("cs_other"), good, body, fixedNow},
		"tampered body":   {key, good, []byte(`{"sub":"uid-2"}`), fixedNow},
		"replayed later":  {key, good, body, fixedNow.Add(Tolerance + time.Second)},
		"from the future": {key, good, body, fixedNow.Add(-Tolerance - time.Second)},
		"missing v1":      {key, "t=1800000000", body, fixedNow},
		"empty header":    {key, "", body, fixedNow},
		"garbage":         {key, "nonsense", body, fixedNow},
	}
	for name, c := range cases {
		if err := Verify(c.key, c.header, c.body, c.now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

type fakeFirebase struct {
	revoked []string
	err     error
}

func (f *fakeFirebase) RevokeRefreshTokens(_ context.Context, uid string) error {
	f.revoked = append(f.revoked, uid)
	return f.err
}

// productServer acts like a product: it checks the signature with its own
// secret and records the subs it was told to revoke.
func productServer(t *testing.T, secret string, status int) (*httptest.Server, *[]string) {
	t.Helper()
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if err := Verify(clients.HashSecret(secret), r.Header.Get(SignatureHeader), body, fixedNow); err != nil {
			t.Errorf("product rejected the signature: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var p Payload
		json.Unmarshal(body, &p)
		if p.Event != EventRevoked {
			t.Errorf("event = %q", p.Event)
		}
		got = append(got, p.Sub)
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

func TestRevokeNotifiesEveryProductAndReportsEachOutcome(t *testing.T) {
	gm2, gm2Got := productServer(t, "cs_gm2", http.StatusNoContent)
	broken, _ := productServer(t, "cs_broken", http.StatusInternalServerError)

	fb := &fakeFirebase{}
	n := NewNotifier(fb)
	n.Now = func() time.Time { return fixedNow }

	targets := []clients.Target{
		{Sub: "uid-1", Email: "a@example.com", ClientName: "GM2", RevokeURL: gm2.URL, SigningKey: clients.HashSecret("cs_gm2")},
		{Sub: "uid-1", Email: "a@example.com", ClientName: "Broken", RevokeURL: broken.URL, SigningKey: clients.HashSecret("cs_broken")},
		{Sub: "uid-1", Email: "a@example.com", ClientName: "NoURL"},
		{Sub: "uid-2", Email: "a@example.com", ClientName: "GM2", RevokeURL: gm2.URL, SigningKey: clients.HashSecret("cs_gm2")},
	}
	results := n.Revoke(context.Background(), targets)

	status := map[string]string{}
	for _, r := range results {
		status[r.Target+"/"+r.Sub] = r.Status
	}
	want := map[string]string{
		"Firebase/uid-1": StatusRevoked,
		"Firebase/uid-2": StatusRevoked,
		"GM2/uid-1":      StatusRevoked,
		"GM2/uid-2":      StatusRevoked,
		"Broken/uid-1":   StatusFailed,
		"NoURL/uid-1":    StatusSkipped,
	}
	for k, v := range want {
		if status[k] != v {
			t.Errorf("%s = %q, want %q (all: %v)", k, status[k], v, status)
		}
	}
	if len(fb.revoked) != 2 {
		t.Errorf("Firebase revoked %v, want each sub once", fb.revoked)
	}
	if len(*gm2Got) != 2 {
		t.Errorf("GM2 received %v, want both subs", *gm2Got)
	}
}

func TestRevokeReportsFirebaseAndNetworkFailures(t *testing.T) {
	down := httptest.NewServer(http.NotFoundHandler())
	url := down.URL
	down.Close()

	n := NewNotifier(&fakeFirebase{err: errors.New("firebase down")})
	results := n.Revoke(context.Background(), []clients.Target{{Sub: "uid-1", ClientName: "GM2", RevokeURL: url, SigningKey: "k"}})

	for _, r := range results {
		if r.Status != StatusFailed || r.Detail == "" {
			t.Errorf("%s: got %+v, want failed with detail", r.Target, r)
		}
	}
}
