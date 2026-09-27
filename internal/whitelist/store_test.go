package whitelist

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/hikahana/auth-poc-test/internal/store"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "whitelist.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return New(db)
}

func TestLookupIsCaseInsensitiveAndOnlyFindsRegisteredAddresses(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.Add(ctx, "  Member.Nutfes@Gmail.com ", RoleMember, "admin"); err != nil {
		t.Fatalf("Add: %v", err)
	}

	e, err := s.Lookup(ctx, "MEMBER.NUTFES@GMAIL.COM")
	if err != nil || e.Role != RoleMember {
		t.Fatalf("Lookup = %+v, %v; want member", e, err)
	}
	if _, err := s.Lookup(ctx, "stranger.nutfes@gmail.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Lookup(stranger) = %v, want ErrNotFound", err)
	}
}

func TestAddIsIdempotentAndKeepsTheOriginalRole(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.Add(ctx, "a@example.com", RoleAdmin, "first"); err != nil {
		t.Fatal(err)
	}
	e, err := s.Add(ctx, "A@example.com", RoleMember, "second")
	if err != nil {
		t.Fatal(err)
	}
	if e.Role != RoleAdmin || e.AddedBy != "first" {
		t.Fatalf("re-adding changed the entry: %+v", e)
	}
	if _, err := s.Add(ctx, "b@example.com", Role("owner"), "x"); err == nil {
		t.Fatal("unknown role should be rejected")
	}
}

func TestTheLastAdminCannotBeRemovedOrDemoted(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	s.Add(ctx, "admin@example.com", RoleAdmin, "seed")
	s.Add(ctx, "member@example.com", RoleMember, "admin@example.com")

	if err := s.Remove(ctx, "admin@example.com"); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("Remove(last admin) = %v, want ErrLastAdmin", err)
	}
	if _, err := s.SetRole(ctx, "admin@example.com", RoleMember); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("SetRole(last admin, member) = %v, want ErrLastAdmin", err)
	}

	// With a second admin, the first can step down and then be removed.
	if _, err := s.SetRole(ctx, "member@example.com", RoleAdmin); err != nil {
		t.Fatalf("promote: %v", err)
	}
	if _, err := s.SetRole(ctx, "admin@example.com", RoleMember); err != nil {
		t.Fatalf("demote with another admin present: %v", err)
	}
	if err := s.Remove(ctx, "admin@example.com"); err != nil {
		t.Fatalf("remove former admin: %v", err)
	}
	if n, _ := s.CountAdmins(ctx); n != 1 {
		t.Fatalf("CountAdmins = %d, want 1", n)
	}
}

func TestSetRoleAndRemoveReportUnknownAddresses(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.SetRole(ctx, "ghost@example.com", RoleAdmin); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SetRole(ghost) = %v, want ErrNotFound", err)
	}
	if err := s.Remove(ctx, "ghost@example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Remove(ghost) = %v, want ErrNotFound", err)
	}
}
