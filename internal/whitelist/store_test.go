package whitelist

import (
	"context"
	"path/filepath"
	"testing"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "whitelist.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestEnsureEntryCreatesPending(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	entry, err := s.EnsureEntry(ctx, "new@example.com")
	if err != nil {
		t.Fatalf("EnsureEntry: %v", err)
	}
	if entry.Status != StatusPending {
		t.Fatalf("want status pending, got %s", entry.Status)
	}

	// Calling it again must not reset an already-decided entry.
	if err := s.SetStatus(ctx, "new@example.com", StatusApproved, "admin"); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	entry, err = s.EnsureEntry(ctx, "new@example.com")
	if err != nil {
		t.Fatalf("EnsureEntry (2nd): %v", err)
	}
	if entry.Status != StatusApproved {
		t.Fatalf("want status approved after re-check, got %s", entry.Status)
	}
}

func TestSetStatusUnknownEmail(t *testing.T) {
	s := newTestStore(t)
	err := s.SetStatus(context.Background(), "ghost@example.com", StatusApproved, "admin")
	if err == nil {
		t.Fatal("want error for unknown email, got nil")
	}
}

func TestListFiltersByStatus(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	for _, email := range []string{"a@example.com", "b@example.com", "c@example.com"} {
		if _, err := s.EnsureEntry(ctx, email); err != nil {
			t.Fatalf("EnsureEntry(%s): %v", email, err)
		}
	}
	if err := s.SetStatus(ctx, "a@example.com", StatusApproved, "admin"); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	if err := s.SetStatus(ctx, "b@example.com", StatusRejected, "admin"); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}

	approved, err := s.List(ctx, StatusApproved)
	if err != nil {
		t.Fatalf("List(approved): %v", err)
	}
	if len(approved) != 1 || approved[0].Email != "a@example.com" {
		t.Fatalf("want [a@example.com] approved, got %+v", approved)
	}

	all, err := s.List(ctx, "")
	if err != nil {
		t.Fatalf("List(all): %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("want 3 entries total, got %d", len(all))
	}
}
