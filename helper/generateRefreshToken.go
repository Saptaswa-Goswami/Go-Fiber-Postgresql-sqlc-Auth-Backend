package helper

import (
	// "auth/config"
	db "auth/db/sqlc"
	"encoding/hex"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func GenerateRefreshToken(user *db.User) (string, error) {
	// if len(config.SecretJwtKeyRefresh) == 0 {
	// 	return "", fmt.Errorf("secret key is empty")
	// }
	SecretJwtKeyRefresh := "abc345getrgh"
	if user.ID == (pgtype.UUID{}) {
		return "", fmt.Errorf("user ID is not present")
	}

	// Convert the UUID to a string
	uuidString := hex.EncodeToString(user.ID.Bytes[:])
	claims := jwt.MapClaims{
		"id":      uuidString,
		"isAdmin": user.IsAdmin,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(SecretJwtKeyRefresh))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}
