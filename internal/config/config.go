package config

import "os"

// Config holds runtime settings loaded from environment variables.
type Config struct {
	Addr                string
	DBPath              string
	FirebaseCredentials string
	AdminAPIKey         string
}

func Load() Config {
	return Config{
		Addr:                getenv("AUTH_PLATFORM_ADDR", ":8080"),
		DBPath:              getenv("AUTH_PLATFORM_DB_PATH", "auth-platform.db"),
		FirebaseCredentials: os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"),
		AdminAPIKey:         os.Getenv("AUTH_PLATFORM_ADMIN_KEY"),
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
