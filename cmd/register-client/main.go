// Command register-client registers a product from the command line and
// prints its credentials, for setting up environments before anyone has
// signed in to the admin screen. The admin screen does the same thing.
//
//	go run ./cmd/register-client GM2 http://localhost:3100/api/auth/platform_revocations
//
// For a product that is already registered, passing a revoke URL updates it
// (no new secret is issued).
package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/hikahana/auth-poc-test/internal/clients"
	"github.com/hikahana/auth-poc-test/internal/config"
	"github.com/hikahana/auth-poc-test/internal/store"
)

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		fmt.Fprintln(os.Stderr, "usage: go run ./cmd/register-client <name> [revoke_url]")
		os.Exit(2)
	}
	name, revokeURL := os.Args[1], ""
	if len(os.Args) == 3 {
		revokeURL = os.Args[2]
	}

	db, err := store.Open(config.Load().DBPath)
	if err != nil {
		fail(err)
	}
	defer db.Close()

	ctx := context.Background()
	cl := clients.New(db)

	existing, err := cl.FindByName(ctx, name)
	switch {
	case err == nil && revokeURL != "":
		if _, err := cl.Update(ctx, existing.ID, nil, &revokeURL); err != nil {
			fail(err)
		}
		fmt.Fprintf(os.Stderr, "%s already exists; revoke_url updated\n", name)
		return
	case err == nil:
		fail(fmt.Errorf("%s already exists; rotate its secret from the admin screen if it was lost", name))
	case !errors.Is(err, clients.ErrNotFound):
		fail(err)
	}

	c, secret, err := cl.Create(ctx, name, revokeURL)
	if err != nil {
		fail(err)
	}
	fmt.Printf("AUTH_PLATFORM_CLIENT_ID=%s\nAUTH_PLATFORM_CLIENT_SECRET=%s\n", c.ID, secret)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
