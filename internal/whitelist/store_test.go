package whitelist

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "whitelist.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOnlyRegisteredAddressesAreAllowed(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.Add(ctx, "  Member.Nutfes@Gmail.com ", "admin"); err != nil {
		t.Fatalf("Add: %v", err)
	}

	for email, want := range map[string]bool{
		"member.nutfes@gmail.com":   true,
		"MEMBER.NUTFES@GMAIL.COM":   true,
		"stranger.nutfes@gmail.com": false,
	} {
		got, err := s.IsAllowed(ctx, email)
		if err != nil {
			t.Fatalf("IsAllowed(%s): %v", email, err)
		}
		if got != want {
			t.Errorf("IsAllowed(%s) = %v, want %v", email, got, want)
		}
	}
}

func TestCheckingAnUnknownAddressDoesNotRegisterIt(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.IsAllowed(ctx, "stranger@example.com"); err != nil {
		t.Fatal(err)
	}
	entries, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("want empty list, got %+v", entries)
	}
}

func TestAddIsIdempotentAndRemoveRevokes(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.Add(ctx, "a@example.com", "first-admin"); err != nil {
		t.Fatal(err)
	}
	entry, err := s.Add(ctx, "A@example.com", "second-admin")
	if err != nil {
		t.Fatalf("second Add: %v", err)
	}
	if entry.AddedBy != "first-admin" {
		t.Errorf("re-adding should keep the original entry, got added_by=%s", entry.AddedBy)
	}

	if err := s.Remove(ctx, "A@EXAMPLE.COM"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if ok, _ := s.IsAllowed(ctx, "a@example.com"); ok {
		t.Fatal("removed address should no longer be allowed")
	}
	if err := s.Remove(ctx, "a@example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removing twice: got %v, want ErrNotFound", err)
	}
}
