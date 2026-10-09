package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"

	"github.com/hikahana/auth-poc-test/internal/api"
	"github.com/hikahana/auth-poc-test/internal/clients"
	"github.com/hikahana/auth-poc-test/internal/config"
	"github.com/hikahana/auth-poc-test/internal/firebaseauth"
	"github.com/hikahana/auth-poc-test/internal/googleauth"
	"github.com/hikahana/auth-poc-test/internal/revocation"
	"github.com/hikahana/auth-poc-test/internal/store"
	"github.com/hikahana/auth-poc-test/internal/whitelist"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	cfg := config.Load()

	ctx := context.Background()

	verifier, err := firebaseauth.NewVerifier(ctx, cfg.FirebaseCredentials)
	if err != nil {
		logger.Error("failed to init firebase verifier", "error", err)
		os.Exit(1)
	}

	google, err := googleauth.NewVerifier(cfg.GoogleClientID)
	if err != nil {
		logger.Error("failed to init google sign-in", "error", err)
		os.Exit(1)
	}

	db, err := store.Open(cfg.DBPath)
	if err != nil {
		logger.Error("failed to open database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	wl := whitelist.New(db)
	if n, err := wl.CountActiveAdmins(ctx); err == nil && n == 0 {
		logger.Warn("no administrator yet — register the first one with: go run ./cmd/seed-admin <email>")
	}

	server := api.NewServer(api.Deps{
		Verifier:     verifier,
		Google:       google,
		CustomTokens: verifier,
		Whitelist:    wl,
		Clients:      clients.New(db),
		Revoker:      revocation.NewNotifier(verifier),
		WebDir:       cfg.WebDir,
		Logger:       logger,
	})

	logger.Info("starting auth platform API", "addr", cfg.Addr)
	if err := http.ListenAndServe(cfg.Addr, server.Routes()); err != nil {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
