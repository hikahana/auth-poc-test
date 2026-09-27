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

	c, secret, err := s.Create(ctx, " GM2 ")
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

	if _, _, err := s.Create(ctx, "GM2"); !errors.Is(err, ErrDuplicateName) {
		t.Fatalf("duplicate name: got %v", err)
	}
}

func TestRotateSecretAndDeactivateCutOffTheOldCredentials(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	c, oldSecret, _ := s.Create(ctx, "FinanSu")

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

	if _, err := s.SetActive(ctx, c.ID, false); err != nil {
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
	gm2, _, _ := s.Create(ctx, "GM2")
	finansu, _, _ := s.Create(ctx, "FinanSu")

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
