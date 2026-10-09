package config

import "os"

// Config holds runtime settings loaded from environment variables.
type Config struct {
	Addr                string
	DBPath              string
	FirebaseCredentials string
	GoogleClientID      string
	WebDir              string
}

func Load() Config {
	return Config{
		WebDir:              getenv("AUTH_PLATFORM_WEB_DIR", "web"),
		Addr:                getenv("AUTH_PLATFORM_ADDR", ":8080"),
		DBPath:              getenv("AUTH_PLATFORM_DB_PATH", "auth-platform.db"),
		FirebaseCredentials: os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"),
		GoogleClientID:      os.Getenv("GOOGLE_OAUTH_CLIENT_ID"),
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
