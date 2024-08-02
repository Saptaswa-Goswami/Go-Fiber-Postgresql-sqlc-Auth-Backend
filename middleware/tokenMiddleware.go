package middleware

import (
	// "auth/config"
	db "auth/db/sqlc"
	"auth/helper"
	"context"
	"errors"
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

var SecretKey = "abc345"

func TokenMiddleware(dbQueries *db.Queries) fiber.Handler {
	return func(c *fiber.Ctx) error {
		tokenString := c.Get("Authorization")
		if tokenString == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "No token provided in tokenmiddleware"})
		}
		if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
			tokenString = tokenString[7:]
		}
		claims, err := validateToken(tokenString)
		if err != nil {
			if errors.Is(err, jwt.ErrTokenExpired) {
				return handleExpiredToken(c, dbQueries, tokenString)
			}
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token in tokenmiddleware ", "Error": err.Error(), "claims": claims})
		}

		userID, ok := claims["id"].(string)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid user ID in token in tokenmiddleware"})
		}

		var userIDUUID pgtype.UUID
		err = userIDUUID.Scan(userID)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid user ID format in tokenmiddleware"})
		}
		user, err := dbQueries.GetUserByID(c.Context(), userIDUUID)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "User not found in tokenmiddleware", "Error": err.Error()})
		}

		c.Locals("user", user)
		c.Locals("accessToken", tokenString)

		return c.Next()
	}
}

func validateToken(tokenString string) (jwt.MapClaims, error) {
	fmt.Printf("Validating token: %s\n", tokenString)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(SecretKey), nil
	})

	if err != nil {
		fmt.Print(err)
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims in validatetoken")
	}

	return claims, nil
}

func handleExpiredToken(c *fiber.Ctx, dbQueries *db.Queries, oldToken string) error {
	// var userID pgtype.UUID
	ctx := context.Background()
	userID, err := dbQueries.GetUserIDByAcsessToken(ctx, oldToken)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token in handelexpire", "err": err.Error()})
	}

	user, err := dbQueries.GetUserByID(c.Context(), userID)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "User not found in handelexpire"})
	}

	newAccessToken, err := helper.GenerateAccessToken(&user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not generate access token in handelexpire"})
	}

	newRefreshToken, err := helper.GenerateRefreshToken(&user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not generate refresh token in handelexpire"})
	}

	// Update tokens in the database
	err = dbQueries.UpdateToken(c.Context(), db.UpdateTokenParams{
		UserID:       user.ID,
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
	})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not update tokens in handelexpire"})
	}

	// Set new tokens in response headers
	c.Set("Authorization", "Bearer "+newAccessToken)
	c.Set("Refresh-Token", newRefreshToken)

	// Update the request context with new token data
	c.Locals("user", user)
	c.Locals("accessToken", newAccessToken)
	c.Locals("refreshToken", newRefreshToken)

	return c.Next()
}

// func generateAccessToken(user *db.User) (string, error) {
// 	claims := jwt.MapClaims{
// 		"id":  user.ID,
// 		"exp": time.Now().Add(TokenDuration).Unix(),
// 	}
// 	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
// 	return token.SignedString([]byte(SecretKey))
// }

// func generateRefreshToken(user *db.User) (string, error) {
// 	claims := jwt.MapClaims{
// 		"id":  user.ID,
// 		"exp": time.Now().Add(TokenDuration * 7).Unix(), // Refresh token lasts 7 times longer
// 	}
// 	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
// 	return token.SignedString([]byte(SecretKey))
// }
