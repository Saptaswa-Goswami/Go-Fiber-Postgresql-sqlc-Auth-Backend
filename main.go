package main

import (
	"auth/config"
	"auth/controllers"
	db "auth/db/sqlc"
	"auth/router"
	"context"
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/jackc/pgx/v5/pgxpool"
)

var queries *db.Queries

func initDB() {
	connStr := "postgresql://postgres:1234@localhost:5432/user-auth?sslmode=disable"

	dbConn, err := pgxpool.New(context.Background(), connStr)
	if err != nil {
		log.Fatalf("Unable to connect to database: %v", err)
	}

	queries = db.New(dbConn)
	log.Println("Database connection established")
}

func main() {

	config.LoadConfig()

	app := fiber.New()

	initDB()

	userController := controllers.NewUserController(queries)

	app.Use(cors.New())
	app.Use(logger.New())

	router.SetupRoutes(app, userController, queries)

	app.Listen(":8082")

}
