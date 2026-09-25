package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"

	"github.com/hikahana/auth-poc-test/internal/api"
	"github.com/hikahana/auth-poc-test/internal/config"
	"github.com/hikahana/auth-poc-test/internal/firebaseauth"
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

	wl, err := whitelist.Open(cfg.DBPath)
	if err != nil {
		logger.Error("failed to open whitelist store", "error", err)
		os.Exit(1)
	}
	defer wl.Close()

	if cfg.AdminAPIKey == "" {
		logger.Warn("AUTH_PLATFORM_ADMIN_KEY is not set — admin endpoints will reject every request")
	}

	server := api.NewServer(verifier, wl, cfg.AdminAPIKey, cfg.WebDir, logger)

	logger.Info("starting auth platform API", "addr", cfg.Addr)
	if err := http.ListenAndServe(cfg.Addr, server.Routes()); err != nil {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
