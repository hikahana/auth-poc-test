package whitelist

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

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

func TestEligibility(t *testing.T) {
	for email, want := range map[string]bool{
		"22.h.hanada.nutfes@gmail.com":   true,
		" 22.H.Hanada.NUTFES@Gmail.com ": true,
		"taro.nutfes@gmail.com":          true,
		".nutfes@gmail.com":              false,
		"nutfes@gmail.com":               false,
		"taro@gmail.com":                 false,
		"taro.nutfes@example.com":        false,
		"taro.nutfes@gmail.com.evil.com": false,
		"s221066@stn.nagaokaut.ac.jp":    false,
	} {
		if got := Eligible(email); got != want {
			t.Errorf("Eligible(%q) = %v, want %v", email, got, want)
		}
	}
}

func TestEntryYear(t *testing.T) {
	cases := map[string]struct {
		year int
		ok   bool
	}{
		"22.h.hanada.nutfes@gmail.com": {22, true},
		"05.a.b.nutfes@gmail.com":      {5, true},
		"taro.nutfes@gmail.com":        {0, false},
		"2022.taro.nutfes@gmail.com":   {0, false},
	}
	for email, want := range cases {
		y, ok := EntryYear(email)
		if y != want.year || ok != want.ok {
			t.Errorf("EntryYear(%q) = %d, %v; want %d, %v", email, y, ok, want.year, want.ok)
		}
	}
}

func TestOnlyEligibleAddressesCanBeAdded(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.Add(ctx, "someone@example.com", RoleMember, "admin"); !errors.Is(err, ErrNotEligible) {
		t.Fatalf("Add(ineligible) = %v, want ErrNotEligible", err)
	}
	if _, err := s.EnsureMember(ctx, "someone@example.com"); !errors.Is(err, ErrNotEligible) {
		t.Fatalf("EnsureMember(ineligible) = %v, want ErrNotEligible", err)
	}

	e, err := s.Add(ctx, "22.Taro.NUTFES@gmail.com", RoleMember, "admin")
	if err != nil || e.Email != "22.taro.nutfes@gmail.com" || !e.Active {
		t.Fatalf("Add = %+v, %v", e, err)
	}
}

func TestEnsureMemberRegistersOnceAndNeverRevivesADisabledEntry(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	e, err := s.EnsureMember(ctx, "23.new.nutfes@gmail.com")
	if err != nil || e.Role != RoleMember || e.AddedBy != AddedByAutoRegistration || !e.Active {
		t.Fatalf("first EnsureMember = %+v, %v", e, err)
	}

	if _, err := s.Disable(ctx, "23.new.nutfes@gmail.com", "admin"); err != nil {
		t.Fatal(err)
	}
	e, err = s.EnsureMember(ctx, "23.new.nutfes@gmail.com")
	if err != nil || e.Active {
		t.Fatalf("EnsureMember after disable = %+v, %v; want the disabled entry", e, err)
	}

	e, err = s.Enable(ctx, "23.new.nutfes@gmail.com")
	if err != nil || !e.Active || e.DisabledAt != nil {
		t.Fatalf("Enable = %+v, %v", e, err)
	}
}

func TestTheLastActiveAdminCannotBeDisabledOrDemoted(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	s.Add(ctx, "admin.nutfes@gmail.com", RoleAdmin, "seed")
	s.Add(ctx, "second.nutfes@gmail.com", RoleAdmin, "admin.nutfes@gmail.com")

	// A disabled admin does not count as a remaining admin.
	if _, err := s.Disable(ctx, "second.nutfes@gmail.com", "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Disable(ctx, "admin.nutfes@gmail.com", "x"); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("Disable(last active admin) = %v, want ErrLastAdmin", err)
	}
	if _, err := s.SetRole(ctx, "admin.nutfes@gmail.com", RoleMember); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("SetRole(last active admin, member) = %v, want ErrLastAdmin", err)
	}

	if _, err := s.Enable(ctx, "second.nutfes@gmail.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Disable(ctx, "admin.nutfes@gmail.com", "x"); err != nil {
		t.Fatalf("disable with another active admin: %v", err)
	}
	if n, _ := s.CountActiveAdmins(ctx); n != 1 {
		t.Fatalf("CountActiveAdmins = %d, want 1", n)
	}
}

func TestDisableIsIdempotentAndReportsUnknownAddresses(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	s.Add(ctx, "a.nutfes@gmail.com", RoleMember, "x")

	if _, err := s.Disable(ctx, "a.nutfes@gmail.com", "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Disable(ctx, "a.nutfes@gmail.com", "x"); err != nil {
		t.Fatalf("second Disable = %v, want nil", err)
	}
	for _, err := range []error{
		func() error { _, err := s.Disable(ctx, "ghost.nutfes@gmail.com", "x"); return err }(),
		func() error { _, err := s.Enable(ctx, "ghost.nutfes@gmail.com"); return err }(),
		func() error { _, err := s.SetRole(ctx, "ghost.nutfes@gmail.com", RoleAdmin); return err }(),
	} {
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("got %v, want ErrNotFound", err)
		}
	}
}

func TestSelectForBulkDisable(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	for _, email := range []string{
		"21.a.nutfes@gmail.com", "22.b.nutfes@gmail.com", "23.c.nutfes@gmail.com",
		"noyear.nutfes@gmail.com", "22.disabled.nutfes@gmail.com",
	} {
		s.EnsureMember(ctx, email)
	}
	s.Add(ctx, "22.admin.nutfes@gmail.com", RoleAdmin, "seed")
	s.Disable(ctx, "22.disabled.nutfes@gmail.com", "x")

	emails := func(c BulkCriteria) []string {
		t.Helper()
		got, err := s.SelectForBulkDisable(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, e := range got {
			out = append(out, e.Email)
		}
		return out
	}
	ptr := func(i int) *int { return &i }

	if got := emails(BulkCriteria{EntryYearTo: ptr(22)}); len(got) != 2 || got[0] != "21.a.nutfes@gmail.com" || got[1] != "22.b.nutfes@gmail.com" {
		t.Errorf("year <= 22 = %v; want 21 and 22, not the admin, the disabled one or the one without a year", got)
	}
	if got := emails(BulkCriteria{EntryYearFrom: ptr(22), EntryYearTo: ptr(22)}); len(got) != 1 || got[0] != "22.b.nutfes@gmail.com" {
		t.Errorf("year == 22 = %v", got)
	}

	now := time.Now().UTC()
	past, future := now.Add(-time.Hour), now.Add(time.Hour)
	if got := emails(BulkCriteria{RegisteredFrom: &past, RegisteredBefore: &future}); len(got) != 4 {
		t.Errorf("registered in the last hour = %v, want the 4 active members", got)
	}
	if got := emails(BulkCriteria{RegisteredBefore: &past}); len(got) != 0 {
		t.Errorf("registered before an hour ago = %v, want none", got)
	}
	if got := emails(BulkCriteria{EntryYearTo: ptr(22), RegisteredBefore: &past}); len(got) != 0 {
		t.Errorf("conditions must combine with AND, got %v", got)
	}

	if _, err := s.SelectForBulkDisable(ctx, BulkCriteria{}); err == nil {
		t.Error("empty criteria should be rejected")
	}
}
