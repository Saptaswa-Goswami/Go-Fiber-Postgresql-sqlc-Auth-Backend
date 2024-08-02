package router

import (
	"auth/controllers"
	db "auth/db/sqlc"
	"auth/middleware"

	"github.com/gofiber/fiber/v2"
)

func SetupRoutes(app *fiber.App, userController *controllers.UserController, dbQueries *db.Queries) {
	app.Post("/api/login", userController.Login)
	app.Post("/api/register", userController.Register)
	app.Delete("/api/delete/:userId", middleware.TokenMiddleware(dbQueries), userController.DeleteUser)
	app.Post("/api/logout", middleware.TokenMiddleware(dbQueries), userController.Logout)
}
