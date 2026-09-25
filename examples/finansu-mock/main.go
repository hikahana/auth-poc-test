package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/hikahana/auth-poc-test/examples/finansu-mock/authplatform"
	"github.com/hikahana/auth-poc-test/examples/finansu-mock/handler"
	"github.com/hikahana/auth-poc-test/examples/finansu-mock/repository"
	"github.com/hikahana/auth-poc-test/examples/finansu-mock/store"
	"github.com/hikahana/auth-poc-test/examples/finansu-mock/usecase"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	db, err := store.Open(getenv("FINANSU_MOCK_DB_PATH", "finansu-mock.db"))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	if err := store.Seed(context.Background(), db); err != nil {
		log.Fatal(err)
	}

	userRep := repository.NewUserRepository(db)
	mailAuthRep := repository.NewMailAuthRepository(db)
	sessionRep := repository.NewSessionRepository(db)
	verifier := authplatform.NewClient(getenv("AUTH_PLATFORM_URL", "http://localhost:8080"))

	h := handler.New(
		usecase.NewMailAuthUseCase(mailAuthRep, sessionRep),
		usecase.NewUserUseCase(userRep, sessionRep),
		usecase.NewFirebaseAuthUseCase(verifier, userRep, mailAuthRep, sessionRep),
	)

	e := echo.New()
	e.Use(middleware.Recover())
	e.Use(middleware.Logger())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: strings.Split(getenv("CORS_ORIGINS", "http://localhost:8080"), ","),
		AllowMethods: []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete},
	}))
	h.Register(e)

	e.Logger.Fatal(e.Start(getenv("FINANSU_MOCK_ADDR", ":3200")))
}
