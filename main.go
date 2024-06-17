package main

import (
	"finmate/config"
	"finmate/controllers"
	"finmate/database"
	"finmate/middlewares"

	"fmt"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
)

func init() {
	config.LoadEnv()
	//database.CreateDatabase()
	database.ConnectDB()
	database.MigrateTable()
}

// Completed
// sort by created at
// sort amount
// sort by date
// filter by category
// jwt token
// email otp verification
// common response structure

// add admin middleware
// add subscriptions
// user list subscriptions

func main() {

	r := chi.NewRouter()

	r.Use(middleware.Logger)

	// auth routes
	r.Post("/signup", controllers.Signup)
	r.Post("/send-email-otp", controllers.SendOTPEmail)
	r.Post("/verify-email", controllers.VerifyEmail)
	r.Post("/login", controllers.Login)
	//r.Post("/logout", controllers.Logout)

	// user routes
	userRoutes := chi.NewRouter()
	r.Mount("/user", userRoutes)
	userRoutes.Use(middlewares.UserAuthMiddleware)
	userRoutes.Get("/validate", controllers.Validate)
	userRoutes.Get("/profile", controllers.Profile)
	userRoutes.Post("/add-record", controllers.AddRecord)
	userRoutes.Get("/list-records", controllers.ListRecords)
	userRoutes.Put("/edit-record/{id}", controllers.EditRecord)
	userRoutes.Delete("/delete-record/{id}", controllers.DeleteRecord)
	userRoutes.Get("/get-record/{id}", controllers.GetRecordByID)
	userRoutes.Get("/search-records", controllers.SearchRecords)
	userRoutes.Get("/count-records", controllers.CountRecords)

	userRoutes.Get("/sort-records", controllers.SortRecords)

	fmt.Println("Server started on :8080")
	http.ListenAndServe(":8080", r)

}
