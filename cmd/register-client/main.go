// Command register-client registers a product from the command line and
// prints its credentials, for setting up environments before anyone has
// signed in to the admin screen. The admin screen does the same thing.
//
//	go run ./cmd/register-client GM2
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/hikahana/auth-poc-test/internal/clients"
	"github.com/hikahana/auth-poc-test/internal/config"
	"github.com/hikahana/auth-poc-test/internal/store"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run ./cmd/register-client <name>")
		os.Exit(2)
	}

	db, err := store.Open(config.Load().DBPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer db.Close()

	c, secret, err := clients.New(db).Create(context.Background(), os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Printf("AUTH_PLATFORM_CLIENT_ID=%s\nAUTH_PLATFORM_CLIENT_SECRET=%s\n", c.ID, secret)
}
