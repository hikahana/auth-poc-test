package clients

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hikahana/auth-poc-test/internal/store"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "clients.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return New(db)
}

func TestCreateAndAuthenticate(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	c, secret, err := s.Create(ctx, " GM2 ", "")
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != "GM2" || !c.IsActive || !strings.HasPrefix(c.ID, "cl_") || !strings.HasPrefix(secret, "cs_") {
		t.Fatalf("unexpected client %+v / secret %q", c, secret)
	}

	if _, err := s.Authenticate(ctx, c.ID, secret); err != nil {
		t.Fatalf("Authenticate with the right secret: %v", err)
	}
	for _, tt := range []struct{ id, secret string }{
		{c.ID, "cs_wrong"},
		{"cl_unknown", secret},
		{c.ID, ""},
	} {
		if _, err := s.Authenticate(ctx, tt.id, tt.secret); !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("Authenticate(%q, %q) = %v, want ErrInvalidCredentials", tt.id, tt.secret, err)
		}
	}

	if _, _, err := s.Create(ctx, "GM2", ""); !errors.Is(err, ErrDuplicateName) {
		t.Fatalf("duplicate name: got %v", err)
	}
}

func TestRotateSecretAndDeactivateCutOffTheOldCredentials(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	c, oldSecret, _ := s.Create(ctx, "FinanSu", "")

	newSecret, err := s.RotateSecret(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, c.ID, oldSecret); !errors.Is(err, ErrInvalidCredentials) {
		t.Error("old secret still works after rotation")
	}
	if _, err := s.Authenticate(ctx, c.ID, newSecret); err != nil {
		t.Errorf("new secret: %v", err)
	}

	inactive := false
	if _, err := s.Update(ctx, c.ID, &inactive, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, c.ID, newSecret); !errors.Is(err, ErrInvalidCredentials) {
		t.Error("deactivated client can still authenticate")
	}

	if _, err := s.RotateSecret(ctx, "cl_unknown"); !errors.Is(err, ErrNotFound) {
		t.Errorf("rotate unknown: %v", err)
	}
}

func TestRecordLoginKeepsOneRowPerLoginAndProduct(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	gm2, _, _ := s.Create(ctx, "GM2", "")
	finansu, _, _ := s.Create(ctx, "FinanSu", "")

	for _, rec := range []struct{ sub, client, email string }{
		{"uid-1", gm2.ID, "Member@Example.com"},
		{"uid-1", gm2.ID, "member@example.com"},
		{"uid-1", finansu.ID, "member@example.com"},
		{"uid-2", gm2.ID, "other@example.com"},
	} {
		if err := s.RecordLogin(ctx, rec.sub, rec.client, rec.email); err != nil {
			t.Fatal(err)
		}
	}

	all, err := s.Logins(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Fatalf("got %d login rows, want 3: %+v", len(all), all)
	}

	mine, err := s.Logins(ctx, "MEMBER@example.com")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, l := range mine {
		names = append(names, l.ClientName)
	}
	if strings.Join(names, ",") != "FinanSu,GM2" {
		t.Fatalf("logins for member = %v, want FinanSu and GM2", names)
	}
}

func TestRevokeURLIsValidatedAndUpdatable(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	for _, bad := range []string{"not a url", "ftp://example.com/x", "/relative/path", "http://"} {
		if _, _, err := s.Create(ctx, "X-"+bad, bad); !errors.Is(err, ErrInvalidRevokeURL) {
			t.Errorf("Create with %q: got %v, want ErrInvalidRevokeURL", bad, err)
		}
	}

	c, _, err := s.Create(ctx, "GM2", "http://localhost:3100/api/auth/platform_revocations")
	if err != nil {
		t.Fatal(err)
	}
	newURL := "https://gm2.example.com/api/auth/platform_revocations"
	updated, err := s.Update(ctx, c.ID, nil, &newURL)
	if err != nil || updated.RevokeURL != newURL || !updated.IsActive {
		t.Fatalf("Update revoke_url = %+v, %v", updated, err)
	}
	bad := "javascript:alert(1)"
	if _, err := s.Update(ctx, c.ID, nil, &bad); !errors.Is(err, ErrInvalidRevokeURL) {
		t.Errorf("Update with bad url: %v", err)
	}
	if found, err := s.FindByName(ctx, " GM2 "); err != nil || found.ID != c.ID {
		t.Errorf("FindByName = %+v, %v", found, err)
	}
}

func TestRevocationTargetsListEveryProductThePersonSignedInTo(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	gm2, gm2Secret, _ := s.Create(ctx, "GM2", "http://gm2/revoke")
	finansu, _, _ := s.Create(ctx, "FinanSu", "")

	s.RecordLogin(ctx, "uid-1", gm2.ID, "member@example.com")
	s.RecordLogin(ctx, "uid-1", finansu.ID, "member@example.com")
	s.RecordLogin(ctx, "uid-9", gm2.ID, "other@example.com")

	targets, err := s.RevocationTargets(ctx, "Member@Example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 || targets[0].ClientName != "FinanSu" || targets[1].ClientName != "GM2" {
		t.Fatalf("targets = %+v", targets)
	}
	if targets[1].RevokeURL != "http://gm2/revoke" || targets[1].SigningKey != HashSecret(gm2Secret) || targets[1].Sub != "uid-1" {
		t.Errorf("GM2 target = %+v", targets[1])
	}

	none, err := s.RevocationTargets(ctx, "never-logged-in@example.com")
	if err != nil || len(none) != 0 {
		t.Errorf("targets for a person who never signed in = %+v, %v", none, err)
	}
}
