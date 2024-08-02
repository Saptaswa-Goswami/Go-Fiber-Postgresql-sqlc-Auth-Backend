package config

import (
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
)

var (
	SecretJwtKeyAccess  string
	SecretJwtKeyRefresh string
	// Add other variables you want to access globally
)

func LoadConfig() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	SecretJwtKeyAccess = os.Getenv("SECRET_JWT_KEY_ACCESS")
	SecretJwtKeyRefresh = os.Getenv("SECRET_JWT_KEY_REFRESH")
	// Load other environment variables

	fmt.Printf("Access Secret key %s\n", SecretJwtKeyAccess)
	fmt.Printf("Secret refresh key %s\n", SecretJwtKeyRefresh)
	// Validate that required variables are set
	if len(SecretJwtKeyAccess) == 0 || len(SecretJwtKeyRefresh) == 0 {
		log.Fatal("Required environment variables are not set")
	}
}
