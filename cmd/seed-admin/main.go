// Command seed-admin registers the first administrator, who can then manage
// everything else from the admin screen. The address is taken as an argument
// rather than from a committed seed file, so it never lands in the repository.
//
//	go run ./cmd/seed-admin you@example.com
package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/hikahana/auth-poc-test/internal/config"
	"github.com/hikahana/auth-poc-test/internal/store"
	"github.com/hikahana/auth-poc-test/internal/whitelist"
)

func main() {
	if len(os.Args) != 2 || !strings.Contains(os.Args[1], "@") {
		fmt.Fprintln(os.Stderr, "usage: go run ./cmd/seed-admin <email>")
		os.Exit(2)
	}
	email := os.Args[1]

	db, err := store.Open(config.Load().DBPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer db.Close()

	ctx := context.Background()
	wl := whitelist.New(db)

	// Add is a no-op for an existing address, so promote explicitly.
	if _, err := wl.Add(ctx, email, whitelist.RoleAdmin, "seed-admin"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	entry, err := wl.SetRole(ctx, email, whitelist.RoleAdmin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Printf("%s is now an administrator\n", entry.Email)
}
