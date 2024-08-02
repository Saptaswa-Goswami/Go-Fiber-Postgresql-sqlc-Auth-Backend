package controllers

import (
	"auth/config"
	db "auth/db/sqlc"
	"auth/helper"
	"context"
	"errors"
	"fmt"
	// "strings"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/crypto/bcrypt"
)

// var SECRET_JWT_KEY_ACCESS = []byte("abc345")
// var SECRET_JWT_KEY_REFRESH = []byte("abc345getrgh")

type UserController struct {
	queries *db.Queries
}

func NewUserController(queries *db.Queries) *UserController {
	return &UserController{queries: queries}
}

// func generateAccessToken(user *db.User) (string, error) {
// 	claims := jwt.MapClaims{
// 		"id":      user.ID,
// 		"isAdmin": user.IsAdmin,
// 		"exp":     time.Now().Add(time.Second * 3600).Unix(),
// 	}
// 	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
// 	tokenString, err := token.SignedString(SECRET_JWT_KEY_ACCESS)
// 	if err != nil {
// 		return "", err
// 	}
// 	return tokenString, nil
// }

// func generateRefreshToken(user *db.User) (string, error) {
// 	claims := jwt.MapClaims{
// 		"id":      user.ID,
// 		"isAdmin": user.IsAdmin,
// 	}
// 	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
// 	tokenString, err := token.SignedString(SECRET_JWT_KEY_ACCESS)
// 	if err != nil {
// 		return "", err
// 	}
// 	return tokenString, nil
// }

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func (uc *UserController) Register(c *fiber.Ctx) error {
	ctx := context.Background()
	response := fiber.Map{
		"statusText": "",
		"msg":        "",
	}
	var user struct {
		Username string `json:"username"`
		Password string `json:"password"`
		IsAdmin  bool   `json:"is_admin"`
	}

	if err := c.BodyParser(&user); err != nil {
		response["msg"] = "Error : Cannot parse JSON"
		response["err"] = err
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}

	hashedPassword, err := HashPassword(user.Password)
	if err != nil {
		response["msg"] = "Error : Failed to hash password"
		return c.Status(fiber.StatusInternalServerError).JSON(response)
	}

	user.Password = hashedPassword
	newUser, err := uc.queries.CreateUser(ctx, db.CreateUserParams{
		Username: user.Username,
		Password: user.Password,
		IsAdmin:  &user.IsAdmin,
	})
	if err != nil {
		response["msg"] = "Error : Failed to create user"
		return c.Status(fiber.StatusInternalServerError).JSON(response)
	}
	response["msg"] = "Registration Successfull"
	response["user"] = newUser
	return c.Status(200).JSON(response)
}

func (uc *UserController) Login(c *fiber.Ctx) error {
	ctx := context.Background()
	response := fiber.Map{
		"StatusText": "",
		"msg":        "",
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.BodyParser(&req); err != nil {
		response["msg"] = "Error : Invalid Request"
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}
	user, err := uc.queries.GetUserByUsername(ctx, req.Username)
	if err != nil {
		response["msg"] = "Error : User does not exists"
		response["Error "] = err.Error()
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}

	if !CheckPasswordHash(req.Password, user.Password) {
		response["msg"] = "Error : Password does not match"
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}

	accessToken, err := helper.GenerateAccessToken(&user)
	if err != nil {
		response["msg"] = "Error : Could not generate access token"
		response["Error : "] = err
		return c.Status(fiber.StatusInternalServerError).JSON(response)
	}

	refreshToken, err := helper.GenerateRefreshToken(&user)
	if err != nil {
		response["msg"] = "Error : Could not generate refresh token"
		response["Error : "] = err
		return c.Status(fiber.StatusInternalServerError).JSON(response)
	}

	_, err = uc.queries.CreateToken(ctx, db.CreateTokenParams{
		UserID:       user.ID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})

	if err != nil {
		response["msg"] = "Error : Could not store token" + err.Error()
		return c.Status(fiber.StatusInternalServerError).JSON(response)
	}

	response["msg"] = "Login Successful"
	response["username"] = user.Username
	response["isAdmin"] = user.IsAdmin
	response["accessToken"] = accessToken
	return c.Status(200).JSON(response)

}

func (uc *UserController) DeleteUser(c *fiber.Ctx) error {
	ctx := context.Background()
	response := fiber.Map{
		"statusText": "",
		"msg":        "",
	}
	//We need to send params userid as string not uuid because in claim it is string
	userID := c.Params("userId")
	parsedUUID, err := uuid.Parse(userID)
	if err != nil {
		response["msg"] = "Error: Invalid user id"
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}
	fmt.Printf("User id from params %v\n", userID)

	fmt.Printf("Parsed uudid User id %v\n", parsedUUID)

	// Extract the token from the Authorization header
	tokenString, err := extractTokenFromHeader(c)
	if err != nil {
		response["msg"] = "Error: " + err.Error()
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}

	// Validate and parse the JWT
	claims, err := validateToken(tokenString)
	if err != nil {
		response["msg"] = "Error: Invalid token " + err.Error()
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}

	// Check if the user has permission to delete
	if !hasDeletePermission(claims, userID) {
		response["msg"] = "Error: You are not allowed to delete this user"
		return c.Status(fiber.StatusForbidden).JSON(response)
	}

	// Delete the user
	if err := uc.queries.DeleteUser(ctx, pgtype.UUID{Bytes: parsedUUID, Valid: true}); err != nil {
		response["msg"] = "Error: Could not delete user"
		return c.Status(fiber.StatusInternalServerError).JSON(response)
	}

	response["msg"] = "User deleted successfully"
	return c.Status(fiber.StatusOK).JSON(response)
}

func (uc *UserController) Logout(c *fiber.Ctx) error {
	ctx := context.Background()
	response := fiber.Map{
		"statusText": "",
		"msg":        "",
	}

	// Extract the token from the Authorization header
	tokenString, err := extractTokenFromHeader(c)
	if err != nil {
		response["msg"] = "Error: " + err.Error()
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}

	// Parse the token
	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(config.SecretJwtKeyAccess), nil
	})

	if err != nil {
		response["msg"] = "Error: Invalid token " + err.Error()
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}

	claimID, ok := claims["id"].(string)
	if !ok {
		response["msg"] = "Error : Failed to get UserId"
		return c.Status(fiber.StatusInternalServerError).JSON(response)
	}
	parsedUUID, err := uuid.Parse(claimID)
	if err != nil {
		response["msg"] = "Error: Invalid user id"
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}

	if err := uc.queries.DeleteToken(ctx, pgtype.UUID{Bytes: parsedUUID, Valid: true}); err != nil {
		response["msg"] = "Error : Failed to delete user"
		return c.Status(fiber.StatusInternalServerError).JSON(response)
	}

	response["msg"] = "Successfully Logged out"
	return c.Status(200).JSON(response)

}

func extractTokenFromHeader(c *fiber.Ctx) (string, error) {
	// authHeader := c.Get("Authorization")
	// if authHeader == "" {
	// 	return "", errors.New("missing Authorization header")
	// }
	// if !strings.HasPrefix(authHeader, "Bearer ") {
	// 	return "", errors.New("invalid Authorization header format")
	// }
	// return authHeader[len("Bearer "):], nil

	tokenString := c.Get("Authorization")
	if tokenString == "" {
		return "", errors.New("no token provided")
	}
	if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
		tokenString = tokenString[7:]
	}
	return tokenString, nil
}

func validateToken(tokenString string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		// Ensure the token algorithm is what you expect
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(config.SecretJwtKeyAccess), nil
	})

	if err != nil || !token.Valid {
		return nil, err
	}

	fmt.Printf("Claims from toke : %v\n", claims)
	return claims, nil
}

func hasDeletePermission(claims jwt.MapClaims, userID string) bool {
	claimID, ok := claims["id"].(string)
	if !ok {
		return false
	}
	isAdmin, ok := claims["isAdmin"].(bool)
	if !ok {
		return false
	}
	return claimID == userID || isAdmin
}
