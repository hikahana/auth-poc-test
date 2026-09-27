package store

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestOpenCreatesTheLatestSchema(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "new.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var version int
	db.QueryRow(`PRAGMA user_version`).Scan(&version)
	if version != len(migrations) {
		t.Fatalf("user_version = %d, want %d", version, len(migrations))
	}
	if _, err := db.Exec(`INSERT INTO allowed_emails (email, added_by, role) VALUES ('a@example.com', 'x', 'admin')`); err != nil {
		t.Fatalf("insert with role: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO allowed_emails (email, added_by, role) VALUES ('b@example.com', 'x', 'owner')`); err == nil {
		t.Fatal("unknown role should be rejected")
	}
}

// A database created before roles existed (user_version 0, table present)
// must upgrade in place and keep its rows as members.
func TestOpenUpgradesAPreRoleDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	old, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(migrations[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(`INSERT INTO allowed_emails (email, added_by) VALUES ('old@example.com', 'x')`); err != nil {
		t.Fatal(err)
	}
	old.Close()

	db, err := Open(path)
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	defer db.Close()

	var role string
	if err := db.QueryRow(`SELECT role FROM allowed_emails WHERE email = 'old@example.com'`).Scan(&role); err != nil {
		t.Fatal(err)
	}
	if role != "member" {
		t.Fatalf("role = %q, want member", role)
	}
}
