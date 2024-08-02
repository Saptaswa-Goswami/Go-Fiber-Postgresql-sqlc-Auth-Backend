package helper

import (
	// "auth/config"
	db "auth/db/sqlc"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func GenerateAccessToken(user *db.User) (string, error) {
	// if len(config.SecretJwtKeyAccess) == 0 {
	// 	return "", fmt.Errorf("secret key is empty")
	// }
	SecretJwtKeyAccess := "abc345"
	if user.ID == (pgtype.UUID{}) {
		return "", fmt.Errorf("user ID is not present")
	}

	// Convert the UUID to a string
	uuidString := hex.EncodeToString(user.ID.Bytes[:])
	claims := jwt.MapClaims{
		"id":      uuidString,
		"isAdmin": user.IsAdmin,
		"exp":     time.Now().Add(time.Second * 3600).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(SecretJwtKeyAccess))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}
