package config

import (
	"os"
	"strings"
)

// Config holds runtime settings loaded from environment variables.
type Config struct {
	Addr                string
	DBPath              string
	FirebaseCredentials string
	AdminEmails         []string
	WebDir              string
}

func Load() Config {
	return Config{
		WebDir:              getenv("AUTH_PLATFORM_WEB_DIR", "web"),
		Addr:                getenv("AUTH_PLATFORM_ADDR", ":8080"),
		DBPath:              getenv("AUTH_PLATFORM_DB_PATH", "auth-platform.db"),
		FirebaseCredentials: os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"),
		AdminEmails:         splitEmails(os.Getenv("AUTH_PLATFORM_ADMIN_EMAILS")),
	}
}

func splitEmails(s string) []string {
	var emails []string
	for _, e := range strings.Split(s, ",") {
		if e = strings.ToLower(strings.TrimSpace(e)); e != "" {
			emails = append(emails, e)
		}
	}
	return emails
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
